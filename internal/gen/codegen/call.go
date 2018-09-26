// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/opcode"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/wa"
)

func genCall(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opSaveOperands(f)

	funcIndex := load.Varuint32()
	if funcIndex >= uint32(len(f.Module.Funcs)) {
		panic(fmt.Errorf("%s: function index out of bounds: %d", op, funcIndex))
	}

	sigIndex := f.Module.Funcs[funcIndex]
	sig := f.Module.Types[sigIndex]

	opCall(f, &f.FuncLinks[funcIndex].L)
	opFinalizeCall(f, sig)
	return
}

func genCallIndirect(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	sigIndex := load.Varuint32()
	if sigIndex >= uint32(len(f.Module.Types)) {
		panic(fmt.Errorf("%s: signature index out of bounds: %d", op, sigIndex))
	}

	sig := f.Module.Types[sigIndex]

	load.Byte() // reserved

	funcIndex := popOperand(f, wa.I32)

	opSaveOperands(f)

	var funcIndexReg reg.R
	if funcIndex.Storage == storage.Reg {
		funcIndexReg = funcIndex.Reg()
	} else {
		funcIndexReg = reg.Result
		asm.Move(f, funcIndexReg, funcIndex)
	}

	opCallIndirect(f, int32(sigIndex), funcIndexReg)
	opFinalizeCall(f, sig)
	return
}

func opFinalizeCall(f *gen.Func, sig wa.FuncType) {
	f.Regs.CheckNoneAllocated()

	opDropCallOperands(f, len(sig.Params))
	pushResultRegOperand(f, sig.Result, true)

	// The called function's initial suspension point was certainly executed
	if len(f.BranchTargets) > 0 {
		getCurrentBlock(f).Suspension = true
	}
}

func opCall(f *gen.Func, l *link.L) {
	var retAddr int32
	if l.Addr != 0 {
		retAddr = asm.Call(&f.Prog, l.Addr)
	} else {
		retAddr = asm.CallMissing(&f.Prog)
	}
	f.MapCallAddr(retAddr)
	if l.Addr == 0 {
		l.AddSite(retAddr)
	}
}

func opCallIndirect(f *gen.Func, sigIndex int32, funcIndexReg reg.R) {
	retAddr := asm.CallIndirect(f, sigIndex, funcIndexReg)
	f.MapCallAddr(retAddr)
}
