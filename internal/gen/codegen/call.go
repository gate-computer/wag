// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/debug"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/wa"
	"github.com/tsavola/wag/wa/opcode"
)

var (
	errCallParamsExceedStack = module.Error("function call parameter count exceeds stack operand count")
	errCallParamTypeMismatch = module.Error("function call argument has wrong type")
)

func genCall(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opSaveOperands(f)

	funcIndex := load.Varuint32()
	if funcIndex >= uint32(len(f.Module.Funcs)) {
		panic(module.Errorf("%s: function index out of bounds: %d", op, funcIndex))
	}

	sig := checkCallOperandCount(f, f.Module.Funcs[funcIndex])
	opCall(f, &f.FuncLinks[funcIndex].L)
	opFinalizeCall(f, sig)
	return
}

func genCallIndirect(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	sigIndex := load.Varuint32()
	if sigIndex >= uint32(len(f.Module.Types)) {
		panic(module.Errorf("%s: signature index out of bounds: %d", op, sigIndex))
	}

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

	sig := checkCallOperandCount(f, sigIndex)
	opCallIndirect(f, int32(sigIndex), funcIndexReg)
	opFinalizeCall(f, sig)
	return
}

func checkCallOperandCount(f *gen.Func, sigIndex uint32) wa.FuncType {
	sig := f.Module.Types[sigIndex]

	if debug.Enabled {
		debug.Printf("sig: %s", sig)
	}

	if len(sig.Params) > f.StackDepth-f.FrameBase {
		panic(errCallParamsExceedStack)
	}

	for i, t := range sig.Params {
		if t != f.Operands[len(f.Operands)-len(sig.Params)+i].Type {
			panic(errCallParamTypeMismatch)
		}
	}

	return sig
}

func opFinalizeCall(f *gen.Func, sig wa.FuncType) {
	f.Regs.CheckNoneAllocated()

	opDropCallOperands(f, len(sig.Params))
	pushResultRegOperand(f, sig.Result)

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
		retAddr = asm.CallMissing(&f.Prog, f.AtomicCallStubs)
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
