// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"encoding/binary"
	"errors"

	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/debug"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/regalloc"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/internal/pan"
	"gate.computer/wag/internal/typedecode"
	"gate.computer/wag/wa"
)

const (
	MaxFuncLocals     = 8190  // Largest value supported by arm64 backend's stack check.
	MaxBranchTableLen = 65520 // Industry standard.
)

var (
	errBlockEndOperands          = module.Error("unexpected number of operands on stack after block")
	errOperandStackNotEmpty      = module.Error("operand stack not empty at end of function")
	errBranchTargetStackNotEmpty = module.Error("branch target stack not empty at end of function")
	errPopNoOperand              = module.Error("block has no operand to pop")
	errDropNoOperand             = module.Error("block has no operand to drop")
)

type operandFrame struct {
	savedBase int
}

func beginFrame(f *gen.Func) (frame operandFrame) {
	frame.savedBase = f.FrameBase
	f.FrameBase = len(f.Operands)

	if debug.Enabled {
		debug.Printf("new frame base: %d", f.FrameBase)
	}
	return
}

func (frame operandFrame) end(f *gen.Func) {
	f.FrameBase = frame.savedBase

	if debug.Enabled {
		debug.Printf("old frame base: %d", f.FrameBase)
	}
}

func pushOperand(f *gen.Func, x operand.O) {
	if debug.Enabled {
		debug.Printf("push operand #%d: %s", len(f.Operands), x)
	}

	f.Operands = append(f.Operands, x)
}

func pushResultRegOperand(f *gen.Func, t wa.Type) {
	if t != wa.Void {
		pushOperand(f, operand.Reg(t, reg.Result))
	}
}

func popOperand(f *gen.Func, t wa.Type) (x operand.O) {
	x = popAnyOperand(f, t)
	if x.Type != t {
		pan.Panic(module.Errorf("operand %s has wrong type; expected %s", x, t))
	}
	return
}

func popAnyOperand(f *gen.Func, fallbackType wa.Type) operand.O {
	i := len(f.Operands) - 1
	if i < f.FrameBase {
		pan.Panic(errPopNoOperand)
	}

	x := f.Operands[i]

	if x.Storage == storage.Unreachable {
		fallback := operand.UnreachableFallback(fallbackType)

		if debug.Enabled {
			debug.Printf("pop operand #%d: %s -> %s", i, x, fallback)
		}

		// Leave the sentinel on the operand stack.
		return fallback
	}

	f.Operands = f.Operands[:i]

	if len(f.Operands) < f.NumStableOperands {
		f.NumStableOperands = len(f.Operands)
	}

	if debug.Enabled {
		debug.Printf("pop operand #%d: %s", i, x)
	}

	return x
}

func genFunction(f *gen.Func, load *loader.L, funcIndex int, sig wa.FuncType, numExtra int, atomicCallStubs bool) {
	*f = gen.Func{
		Prog: f.Prog,

		Regs:            regalloc.Make(),
		NumExtra:        numExtra,
		Operands:        f.Operands[:0],
		BranchTargets:   f.BranchTargets[:0],
		BranchTables:    f.BranchTables[:0],
		AtomicCallStubs: atomicCallStubs,
	}

	if debug.Enabled {
		debug.Printf("function %d %s", funcIndex, sig)
		debug.Depth++
	}

	asm.AlignFunc(&f.Prog)
	addr := f.Text.Addr
	f.FuncLinks[funcIndex].Addr = addr
	f.Map.PutFuncAddr(uint32(addr))
	stackCheckAddr := asm.SetupStackFrame(f)

	// Discard the function body size after PutFuncAddr so that the object
	// mapper can observe source function positions in co-operation with the
	// reader.
	load.Varuint32()

	if len(sig.Results) > 0 {
		f.ResultType = sig.Results[0]
	}
	f.LocalTypes = sig.Params

	for range load.Span(MaxFuncLocals, "function local group") {
		count := load.Varuint32()
		if uint64(len(f.LocalTypes))+uint64(count) >= MaxFuncLocals {
			pan.Panic(module.Errorf("function #%d has too many variables: %d (at least)", funcIndex, len(f.LocalTypes)))
		}

		t := typedecode.Value(load.Varint7())

		types := make([]wa.Type, len(f.LocalTypes), len(f.LocalTypes)+int(count))
		copy(types, f.LocalTypes)
		for i := uint32(0); i < count; i++ {
			types = append(types, t)
		}
		f.LocalTypes = types
	}

	f.NumParams = len(sig.Params)
	f.NumLocals = len(f.LocalTypes) - f.NumParams

	asm.PushZeros(&f.Prog, f.NumLocals)

	pushBranchTarget(f, f.ResultType, true)

	genOps(f, load)

	deadend := f.BranchTargets[0].Block.Deadend
	if deadend {
		if debug.Enabled {
			debug.Printf("body is a deadend")
		}
	}

	var result operand.O
	if f.ResultType != wa.Void {
		result = popOperand(f, f.ResultType)
	}

	if len(f.Operands) > 0 && f.Operands[len(f.Operands)-1].Storage != storage.Unreachable {
		pan.Panic(errOperandStackNotEmpty)
	}

	if !deadend {
		switch f.ResultType {
		case wa.Void:
			asm.ClearIntResultReg(&f.Prog)

		case wa.I32:
			if zeroExt := asm.Move(f, reg.Result, result); !zeroExt {
				asm.ZeroExtendResultReg(&f.Prog)
			}

		case wa.I64:
			asm.Move(f, reg.Result, result)

		default:
			asm.Move(f, reg.Result, result)
			asm.ClearIntResultReg(&f.Prog)
		}

		f.Regs.CheckNoneAllocated()
	}

	end := popBranchTarget(f)
	label(f, end)
	linker.UpdateFarBranches(f.Text.Bytes(), end)

	asm.Return(&f.Prog, f.NumExtra+f.NumLocals+f.StackDepth)

	if len(f.BranchTargets) != 0 {
		pan.Panic(errBranchTargetStackNotEmpty)
	}

	fullText := f.Text.Bytes()

	linker.UpdateStackCheck(fullText, stackCheckAddr, f.NumExtra+f.NumLocals+f.MaxStackDepth)

	for i, table := range f.BranchTables {
		buf := fullText[table.Addr:]
		for j, target := range table.Targets {
			targetAddr := uint32(target.Label.FinalAddr())
			if table.StackDepth < 0 {
				// Common depth
				binary.LittleEndian.PutUint32(buf[:4], targetAddr)
				buf = buf[4:]

				if debug.Enabled {
					if j < 10 {
						debug.Printf("branch table #%d target #%d: addr %d", i, j, targetAddr)
					} else if j == 10 {
						debug.Printf("...")
					}
				}
			} else {
				deltaSize := int32((table.StackDepth - target.StackDepth) * obj.Word)
				packed := uint64(uint32(deltaSize))<<32 | uint64(targetAddr)
				binary.LittleEndian.PutUint64(buf[:8], packed)
				buf = buf[8:]

				if debug.Enabled {
					if j < 10 {
						debug.Printf("branch table #%d target #%d: addr %d, stack delta %d bytes", i, j, targetAddr, deltaSize)
					} else if j == 10 {
						debug.Printf("...")
					}
				}
			}
		}
	}

	if debug.Enabled {
		debug.Depth--
		if debug.Depth != 0 {
			panic("OMG")
		}
		debug.Printf("functioned")
	}
}

func opStabilizeOperands(f *gen.Func) {
restart:
	for i := f.NumStableOperands; i < len(f.Operands); i++ {
		x := &f.Operands[i]

		if debug.Enabled {
			debug.Printf("stabilize operand #%d: %s", i, *x)
			debug.Depth++
		}

		switch {
		case x.Storage == storage.Reg && x.Reg() == reg.Result:
			r, operandsChanged := opAllocReg(f, x.Type)
			if operandsChanged {
				if debug.Enabled {
					debug.Depth--
					debug.Printf("restart")
				}
				f.Regs.Free(x.Type, r)
				goto restart
			}

			asm.MoveReg(&f.Prog, x.Type, r, reg.Result)
			x.SetReg(r)

		case x.Storage == storage.Flags:
			r, operandsChanged := opAllocReg(f, x.Type)
			if operandsChanged {
				if debug.Enabled {
					debug.Depth--
					debug.Printf("restart")
				}
				f.Regs.Free(x.Type, r)
				goto restart
			}

			asm.SetBool(&f.Prog, r, x.FlagsCond())
			x.SetReg(r)

		default:
			if debug.Enabled {
				debug.Depth--
			}
			continue
		}

		if debug.Enabled {
			debug.Depth--
			debug.Printf("operand #%d stabilized: %s", i, *x)
		}
	}

	f.NumStableOperands = len(f.Operands)
}

func opSaveOperands(f *gen.Func) {
	for i := f.StackDepth; i < len(f.Operands); i++ {
		x := &f.Operands[i]

		if x.Storage == storage.Unreachable {
			continue
		}

		if debug.Enabled {
			debug.Printf("save operand #%d: %s", i, *x)
			debug.Depth++
		}

		opReserveStackEntry(f)

		switch x.Storage {
		case storage.Imm:
			asm.PushImm(&f.Prog, x.ImmValue())
			x.SetStack()

		case storage.Reg:
			asm.PushReg(&f.Prog, x.Type, x.Reg())
			f.Regs.Free(x.Type, x.Reg())
			x.SetStack()

		case storage.Flags:
			asm.PushCond(&f.Prog, x.FlagsCond())
			x.SetStack()

		default:
			if debug.Enabled {
				debug.Depth--
			}
			continue
		}

		if debug.Enabled {
			debug.Depth--
			debug.Printf("operand #%d saved: %s", i, *x)
		}
	}

	f.NumStableOperands = len(f.Operands)
}

func opReserveStackEntry(f *gen.Func) {
	f.StackDepth++
	if f.StackDepth > f.MaxStackDepth {
		f.MaxStackDepth = f.StackDepth
	}

	if debug.Enabled {
		debug.Printf("stack depth: %d (after pushing 1)", f.StackDepth)
	}
}

// opReleaseStackEntry is opReserveStackEntry's counterpart.
func opReleaseStackEntry(f *gen.Func) {
	f.StackDepth--

	if debug.Enabled {
		debug.Printf("stack depth: %d (after dropping 1)", f.StackDepth)
	}
}

func opDropOperand(f *gen.Func) {
	i := len(f.Operands) - 1
	for i < f.FrameBase {
		pan.Panic(errDropNoOperand)
	}

	x := f.Operands[i]

	if debug.Enabled {
		debug.Printf("drop operand #%d: %s", i, x)
	}

	if x.Storage == storage.Unreachable {
		return
	}

	f.Operands = f.Operands[:i]

	if len(f.Operands) < f.NumStableOperands {
		f.NumStableOperands = len(f.Operands)
	}

	switch x.Storage {
	case storage.Stack:
		asm.DropStackValues(&f.Prog, 1)
		f.StackDepth--

		if debug.Enabled {
			debug.Printf("stack depth: %d (after dropping 1)", f.StackDepth)
		}

	case storage.Reg:
		f.Regs.Free(x.Type, x.Reg())
	}
}

// opDropCallOperands caller knows for sure that the dropped operands are stack
// operands within the current block.
func opDropCallOperands(f *gen.Func, paramCount int) {
	if paramCount == 0 {
		return
	}

	var dropCount int

	for i := len(f.Operands) - 1; i >= len(f.Operands)-paramCount; i-- {
		x := f.Operands[i]

		if x.Storage == storage.Unreachable {
			if debug.Enabled {
				debug.Printf("unreachable call operands: %d", paramCount-dropCount)
			}
			break
		}

		dropCount++

		if debug.Enabled {
			debug.Printf("drop call operand #%d: %s", i, x)
		}
	}

	asm.DropStackValues(&f.Prog, dropCount)
	f.StackDepth -= dropCount

	if debug.Enabled {
		debug.Printf("stack depth: %d (after dropping %d)", f.StackDepth, dropCount)
	}

	f.Operands = f.Operands[:len(f.Operands)-dropCount]

	if len(f.Operands) < f.NumStableOperands {
		f.NumStableOperands = len(f.Operands)
	}
}

func truncateBlockOperands(f *gen.Func, deadend bool) {
	if deadend {
		truncateUnreachableBlockOperands(f)
		return
	}

	if len(f.Operands) != f.FrameBase {
		pan.Panic(errBlockEndOperands)
	}
}

func truncateUnreachableBlockOperands(f *gen.Func) {
	top := len(f.Operands) - 1
	if top < f.FrameBase {
		panic("no unreachable sentinel on operand stack after deadend block")
	}
	if f.Operands[top].Storage != storage.Unreachable {
		pan.Panic(errBlockEndOperands)
	}

	for i := f.FrameBase; i < top; i++ {
		x := f.Operands[i]

		if debug.Enabled {
			debug.Printf("truncate operand #%d: %s", i, x)
		}

		switch x.Storage {
		case storage.Stack:
			// Deadend; no need to generate instructions.
			f.StackDepth--

		case storage.Reg:
			f.Regs.Free(x.Type, x.Reg())
		}
	}

	if debug.Enabled {
		debug.Printf("stack depth: %d", f.StackDepth)
	}

	f.Operands = f.Operands[:f.FrameBase]

	if len(f.Operands) < f.NumStableOperands {
		f.NumStableOperands = len(f.Operands)
	}
}

func opStealOperandReg(f *gen.Func, t wa.Type) reg.R {
	return opStealOperandRegBefore(f, t, len(f.Operands))
}

func opStealOperandRegBefore(f *gen.Func, t wa.Type, length int) reg.R {
	for i := f.StackDepth; i < length; i++ {
		x := &f.Operands[i]

		if debug.Enabled {
			debug.Printf("save operand #%d: %s", i, *x)
			debug.Depth++
		}

		if x.Storage == storage.Unreachable {
			length++
			continue
		}

		opReserveStackEntry(f)

		switch x.Storage {
		case storage.Imm:
			asm.PushImm(&f.Prog, x.ImmValue())
			x.SetStack()

		case storage.Reg:
			r := x.Reg()
			asm.PushReg(&f.Prog, x.Type, r)
			x.SetStack()

			if r != reg.Result {
				if x.Type.Category() == t.Category() {
					if debug.Enabled {
						debug.Depth--
						debug.Printf("operand #%d saved: %s", i, *x)
					}

					i++ // This operand was stabilized too.

					// There may be unconsumed stack values that have already
					// been popped from operand stack.
					if f.NumStableOperands < i {
						f.NumStableOperands = i
					}

					return r
				}

				f.Regs.Free(x.Type, r)
			}

		case storage.Flags:
			asm.PushCond(&f.Prog, x.FlagsCond())
			x.SetStack()

		default:
			if debug.Enabled {
				debug.Depth--
			}
			continue
		}

		if debug.Enabled {
			debug.Depth--
			debug.Printf("operand #%d saved: %s", i, *x)
		}
	}

	panic(pan.Wrap(errors.New("no allocated registers found in operand stack while under register pressure")))
}

func opAllocReg(f *gen.Func, t wa.Type) (r reg.R, operandsChanged bool) {
	r = f.Regs.AllocResult(t)
	if r == reg.Result {
		r = opStealOperandReg(f, t)
		operandsChanged = true
	}
	return
}

func opMoveResult(f *gen.Func, source operand.O, deadend bool) {
	if !deadend {
		asm.Move(f, reg.Result, source)
	} else {
		f.ValueBecameUnreachable(source)
	}
}
