// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"fmt"

	"gate.computer/wag/internal/gen/debug"
	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/regalloc"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/wa"
	"import.name/pan"
)

type Block struct {
	Suspension bool
}

type BranchTarget struct {
	Label      link.L
	StackDepth int
	ValueType  wa.Type
	FuncEnd    bool

	Block Block
}

type BranchTable struct {
	Addr       int32
	Targets    []*BranchTarget
	StackDepth int // -1 indicates common depth among all targets
}

type Func struct {
	Prog // Initialized by GenProgram, preserved by GenFunction

	Regs regalloc.Allocator

	ResultType wa.Type
	LocalTypes []wa.Type
	NumParams  int
	NumLocals  int // The non-param ones
	NumExtra   int // Library function's duplicated arguments etc.

	Operands          []operand.O
	FrameBase         int // Number of (stack) operands belonging to parent blocks
	NumStableOperands int
	StackDepth        int // The dynamic entries after locals
	MaxStackDepth     int

	BranchTargets []*BranchTarget
	BranchTables  []BranchTable

	AtomicCallStubs bool
}

func (f *Func) LocalOffset(index int) int32 {
	// Params are in behind function link address slot
	n := f.StackDepth + f.NumLocals + f.NumParams - index
	if index >= f.NumParams {
		// Other locals are on this side of function link address slot
		n--
	}
	if n < 0 {
		pan.Panic(fmt.Errorf("effective stack offset of local variable #%d is negative", index))
	}
	return int32(n * obj.Word)
}

// StackValueConsumed updates the virtual stack pointer on behalf of
// MacroAssembler when it changes the physical stack pointer.
func (f *Func) StackValueConsumed() {
	f.StackDepth--

	if debug.Enabled {
		debug.Printf("stack depth: %d (pop 1)", f.StackDepth)
	}
}

// ValueBecameUnreachable keeps the state consistent when an operand will not
// be operated on (because it was popped on an unreachable code path).
func (f *Func) ValueBecameUnreachable(x operand.O) {
	switch x.Storage {
	case storage.Stack:
		f.StackValueConsumed()

	case storage.Reg:
		if x.Reg() != reg.Result {
			f.Regs.Free(x.Type, x.Reg())
		}
	}
}

func (f *Func) MapCallAddr(retAddr int32) {
	f.Map.PutCallSite(uint32(retAddr), f.mapStackUsage())
	f.LastCallAddr = retAddr // Needed only by arm64 backend.
}

func (f *Func) mapStackUsage() int32 {
	// Add one entry for link address.
	return int32((f.NumLocals + f.StackDepth + 1) * obj.Word)
}
