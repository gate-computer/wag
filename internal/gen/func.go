// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"github.com/tsavola/wag/internal/gen/debug"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/regalloc"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/wa"
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
	RODataAddr int32
	Targets    []*BranchTarget
	StackDepth int // -1 indicates common depth among all targets
}

type TrapTrampoline struct {
	stackDepth int
	addr       int32
}

func (t *TrapTrampoline) Init(f *Func) {
	t.stackDepth = f.StackDepth
	t.addr = f.Text.Addr
}

func (t *TrapTrampoline) Addr(f *Func) (addr int32) {
	if t.stackDepth == f.StackDepth {
		addr = t.addr
	}
	return
}

type Func struct {
	*Prog
	Module *module.M

	Regs regalloc.Allocator

	ResultType wa.Type
	LocalTypes []wa.Type
	NumParams  int
	NumLocals  int // The non-param ones

	Operands          []operand.O
	FrameBase         int // Number of (stack) operands belonging on to parent blocks
	NumStableOperands int
	StackDepth        int // The dynamic entries after locals
	MaxStackDepth     int

	BranchTargets []*BranchTarget
	BranchTables  []BranchTable

	MemoryOutOfBounds TrapTrampoline
}

func (f *Func) LocalOffset(index int) int32 {
	// Params are in behind function link address slot
	n := f.StackDepth + f.NumLocals + f.NumParams - index
	if index >= f.NumParams {
		// Other locals are on this side of function link address slot
		n--
	}
	if n < 0 {
		panic("effective stack offset of local variable #%d is negative")
	}
	return int32(n * obj.Word)
}

// StackValueConsumed updates the virtual stack pointer on behalf of
// MacroAssembler when it changes the physical stack pointer.
func (f *Func) StackValueConsumed() {
	f.StackDepth--
	debug.Printf("stack depth: %d (pop 1)", f.StackDepth)
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
	f.Map.PutCallSite(retAddr, int32((f.NumLocals+f.StackDepth+1)*obj.Word)) // +1 for link address
}
