// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/regalloc"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/object"
)

func mapCallAddr(f *function, retAddr int32) {
	f.Map.PutCallSite(object.TextAddr(retAddr), f.stackOffset+gen.WordSize)
}

func genCall(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	funcIndex := load.Varuint32()
	if funcIndex >= uint32(len(f.FuncSigs)) {
		panic(fmt.Errorf("%s: function index out of bounds: %d", op, funcIndex))
	}

	sigIndex := f.FuncSigs[funcIndex]
	sig := f.Sigs[sigIndex]

	numStackParams := setupCallOperands(f, op, sig, values.Operand{})

	opCall(f, &f.FuncLinks[funcIndex].L)
	opBackoffStackPtr(f, numStackParams*gen.WordSize)
	return
}

func genCallIndirect(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	sigIndex := load.Varuint32()
	if sigIndex >= uint32(len(f.Sigs)) {
		panic(fmt.Errorf("%s: signature index out of bounds: %d", op, sigIndex))
	}

	sig := f.Sigs[sigIndex]

	load.Byte() // reserved

	funcIndex := opMaterializeOperand(f, popOperand(f))
	if funcIndex.Type != abi.I32 {
		panic(fmt.Errorf("%s: function index operand has wrong type: %s", op, funcIndex.Type))
	}

	numStackParams := setupCallOperands(f, op, sig, funcIndex)

	// if funcIndex is a reg, it was already relocated to result reg.
	// otherwise it wasn't touched.
	if !funcIndex.Storage.IsReg() {
		opMove(f, regs.Result, funcIndex, false)
	}

	retAddr := isa.OpCallIndirect(&f.Text, f, int32(len(f.TableFuncs)), int32(sigIndex))
	mapCallAddr(f, retAddr)
	opBackoffStackPtr(f, numStackParams*gen.WordSize)
	return
}

func setupCallOperands(f *function, op Opcode, sig abi.Sig, indirect values.Operand) (numStackParams int32) {
	opStackCheck(f)

	args := popOperands(f, len(sig.Args))

	opInitVars(f)
	opSaveTemporaryOperands(f)
	opStoreRegVars(f)

	f.Regs.FreeAll()

	var regArgs regalloc.Map

	for i, value := range args {
		if value.Type != sig.Args[i] {
			panic(fmt.Errorf("%s argument #%d has wrong type: %s", op, i, value.Type))
		}

		var reg regs.R
		var ok bool

		switch value.Storage {
		case values.TempReg:
			reg = value.Reg()
			ok = true

		case values.VarReference:
			if x := f.vars[value.VarIndex()].cache; x.Storage == values.VarReg {
				reg = x.Reg()
				ok = true
				args[i] = x // help the next args loop
			}
		}

		if ok {
			cat := gen.TypeRegCategory(value.Type)

			f.Regs.SetAllocated(cat, reg)
			regArgs.Set(cat, reg, i)
		}
	}

	// relocate indirect index to result reg if it already occupies some reg
	if indirect.Storage.IsReg() && indirect.Reg() != regs.Result {
		if i := regArgs.Get(gen.RegCategoryInt, regs.Result); i >= 0 {
			debugf("indirect call index: %s <-> %s", regs.Result, indirect)
			isa.OpSwap(&f.Text, gen.RegCategoryInt, regs.Result, indirect.Reg())

			args[i] = values.TempRegOperand(args[i].Type, indirect.Reg(), args[i].RegZeroExt())
			regArgs.Clear(gen.RegCategoryInt, regs.Result)
			regArgs.Set(gen.RegCategoryInt, indirect.Reg(), i)
		} else {
			debugf("indirect call index: %s <- %s", regs.Result, indirect)
			isa.OpMoveReg(&f.Text, abi.I32, regs.Result, indirect.Reg())
		}
	}

	var paramRegs regalloc.Iterator
	numStackParams = paramRegs.Init(isa.ParamRegs(), sig.Args)

	var numMissingStackArgs int32

	for _, x := range args[:numStackParams] {
		if x.Storage != values.Stack {
			numMissingStackArgs++
		}
	}

	if numMissingStackArgs > 0 {
		opAdvanceStackPtr(f, numMissingStackArgs*gen.WordSize)

		sourceIndex := numMissingStackArgs
		targetIndex := int32(0)

		// move the register args forward which are currently on stack
		for i := int32(len(args)) - 1; i >= numStackParams; i-- {
			if args[i].Storage == values.Stack {
				debugf("call param #%d: stack (temporary) <- %s", i, args[i])
				isa.OpCopyStack(&f.Text, targetIndex*gen.WordSize, sourceIndex*gen.WordSize)
				sourceIndex++
				targetIndex++
			}
		}

		// move the stack args forward which are already on stack, while
		// inserting the missing stack args
		for i := numStackParams - 1; i >= 0; i-- {
			x := args[i]

			switch x.Storage {
			case values.Stack:
				debugf("call param #%d: stack <- %s", i, x)
				isa.OpCopyStack(&f.Text, targetIndex*gen.WordSize, sourceIndex*gen.WordSize)
				sourceIndex++

			default:
				x = effectiveOperand(f, x)
				debugf("call param #%d: stack <- %s", i, x)
				isa.OpStoreStack(&f.Text, f, targetIndex*gen.WordSize, x)
			}

			targetIndex++
		}
	}

	// uniquify register operands
	for i, value := range args {
		if value.Storage == values.VarReg {
			cat := gen.TypeRegCategory(value.Type)

			if regArgs.Get(cat, value.Reg()) != i {
				reg, ok := tryAllocReg(f, value.Type)
				if !ok {
					panic("not enough registers for all register args")
				}

				debugf("call param #%d: %s %s <- %s", i, cat, reg, value.Reg())
				isa.OpMoveReg(&f.Text, value.Type, reg, value.Reg())

				args[i] = values.RegOperand(false, value.Type, reg)
				regArgs.Set(cat, reg, i)
			}
		}
	}

	f.Regs.FreeAll()

	var preserveFlags bool

	for i := numStackParams; i < int32(len(args)); i++ {
		value := args[i]
		cat := gen.TypeRegCategory(value.Type)
		posReg := paramRegs.IterForward(cat)

		switch {
		case value.Storage.IsReg(): // Vars backed by RegVars were replaced by earlier loop
			if value.Reg() == posReg {
				debugf("call param #%d: %s %s already in place", i, cat, posReg)
			} else {
				if otherArgIndex := regArgs.Get(cat, posReg); otherArgIndex >= 0 {
					debugf("call param #%d: %s %s <-> %s", i, cat, posReg, value.Reg())
					isa.OpSwap(&f.Text, cat, posReg, value.Reg())

					args[otherArgIndex] = value
					regArgs.Set(cat, value.Reg(), otherArgIndex)
				} else {
					debugf("call param #%d: %s %s <- %s", i, cat, posReg, value.Reg())
					isa.OpMoveReg(&f.Text, value.Type, posReg, value.Reg())
				}
			}

		case value.Storage == values.ConditionFlags:
			preserveFlags = true
		}
	}

	paramRegs.InitRegs(isa.ParamRegs())

	for i := int32(len(args)) - 1; i >= numStackParams; i-- {
		value := args[i]
		cat := gen.TypeRegCategory(value.Type)
		posReg := paramRegs.IterBackward(cat)

		if !value.Storage.IsReg() {
			debugf("call param #%d: %s %s <- %s", i, cat, posReg, value)
			opMove(f, posReg, value, preserveFlags)
		}
	}

	for i := range f.vars {
		if v := &f.vars[i]; v.cache.Storage == values.VarReg {
			debugf("forget register variable #%d", i)
			// reg was already stored and freed
			v.resetCache()
		}
	}

	// account for the return address
	if n := f.stackOffset + gen.WordSize; n > f.maxStackOffset {
		f.maxStackOffset = n
	}

	if sig.Result != abi.Void {
		pushResultRegOperand(f, sig.Result)
	}

	return
}

func opCall(f *function, l *links.L) {
	retAddr := isa.OpCall(&f.Text, l.Addr)
	mapCallAddr(f, retAddr)
	if l.Addr == 0 {
		l.AddSite(retAddr)
	}
}
