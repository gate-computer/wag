// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/link"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/internal/regalloc"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/trap"
)

type BranchTarget struct {
	Label       link.L
	StackOffset int32
	ValueType   abi.Type
	FuncEnd     bool
}

type BranchTable struct {
	RODataAddr      int32
	Targets         []*BranchTarget
	CodeStackOffset int32 // -1 indicates common offset
}

type TrapTrampoline struct {
	StackOffset int32
	Link        link.L
}

type Func struct {
	*module.M
	*Prog

	Regs regalloc.Allocator

	ResultType abi.Type

	Vars           []VarState
	NumStackParams int32
	NumInitedVars  int32

	StackOffset    int32
	MaxStackOffset int32
	StackCheckAddr int32

	Operands              []values.Operand
	MinBlockOperand       int
	NumStableOperands     int
	NumPersistentOperands int

	BranchTargets []*BranchTarget
	BranchTables  []BranchTable

	TrapTrampolines [trap.NumTraps]TrapTrampoline
}

func (f *Func) Consumed(x values.Operand) {
	switch x.Storage {
	case values.TempReg:
		f.Regs.Free(x.Type, x.Reg())

	case values.Stack:
		f.StackOffset -= obj.Word
	}
}

func (f *Func) TrapTrampolineAddr(id trap.Id) (addr int32) {
	t := &f.TrapTrampolines[id]
	if t.StackOffset == f.StackOffset {
		addr = t.Link.Addr
	}
	return
}

func (f *Func) InitTrapTrampoline(id trap.Id) {
	t := &f.TrapTrampolines[id]
	t.StackOffset = f.StackOffset
	t.Link.Addr = f.Text.Addr
}

func (f *Func) MapCallAddr(retAddr int32) {
	f.Map.PutCallSite(retAddr, f.StackOffset+obj.Word)
}
