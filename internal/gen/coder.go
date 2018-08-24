// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/mod"
	"github.com/tsavola/wag/internal/regalloc"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/trap"
)

const (
	WordSize     = 8              // stack entry size
	StackReserve = WordSize + 128 // trap/import call return address + red zone
)

type BranchTarget struct {
	Label       links.L
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
	Link        links.L
}

type Func struct {
	*mod.M

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
		f.StackOffset -= WordSize
	}
}

func (f *Func) TrapTrampolineAddr(id trap.Id) (addr int32) {
	t := &f.TrapTrampolines[id]
	if t.StackOffset == f.StackOffset {
		addr = t.Link.Addr
	}
	return
}
