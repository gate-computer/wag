// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/debug"
	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/wa"
	"gate.computer/wag/wa/opcode"
	"import.name/pan"
)

var (
	errCallParamsExceedStack = module.Error("function call parameter count exceeds stack operand count")
	errCallParamTypeMismatch = module.Error("function call argument has wrong type")
	errUnknownTable          = module.Error("unknown table")
)

func checkCallFuncIndex(f *gen.Func, op opcode.Opcode, index uint32) {
	if index >= uint32(len(f.Module.Funcs)) {
		pan.Panic(module.Errorf("%s: function index out of bounds: %d", op, index))
	}
}

func checkIndirectCallTypeIndex(f *gen.Func, op opcode.Opcode, index uint32) uint32 {
	if !f.Module.Table {
		pan.Panic(errUnknownTable)
	}

	if index >= uint32(len(f.Module.Types)) {
		pan.Panic(module.Errorf("%s: signature index out of bounds: %d", op, index))
	}
	return index
}

func genCall(f *gen.Func, load *loader.L, op opcode.Opcode) {
	opSaveOperands(f)

	funcIndex := load.Varuint32()

	if f.ImportContext != nil {
		opCallInImportFunc(f, funcIndex)
	} else {
		opCallInNormalFunc(f, op, funcIndex)
	}
}

func opCallInNormalFunc(f *gen.Func, op opcode.Opcode, funcIndex uint32) {
	checkCallFuncIndex(f, op, funcIndex)

	sig := f.Module.Types[f.Module.Funcs[funcIndex]]
	checkCallOperandCount(f, sig)
	opCall(f, &f.FuncLinks[funcIndex].L)

	// The called function's initial suspension point was certainly executed.
	if len(f.BranchTargets) > 0 {
		getCurrentBlock(f).Suspension = true
	}

	opFinalizeCall(f, sig)
}

func opCallInImportFunc(f *gen.Func, funcIndex uint32) {
	imp := f.ImportContext.ImportFuncs[funcIndex]
	sig := f.ImportContext.Types[f.ImportContext.Funcs[funcIndex]]
	checkCallOperandCount(f, sig)
	asm.CallImportVector(f, imp.VectorIndex)
	f.MapCallAddr(f.Text.Addr)
	opFinalizeCall(f, sig)
}

func genCallIndirect(f *gen.Func, load *loader.L, op opcode.Opcode) {
	sigIndex := checkIndirectCallTypeIndex(f, op, load.Varuint32())
	sigIndex = f.Module.GetCanonicalTypeIndex(sigIndex)

	if load.Byte() != 0 {
		pan.Panic(module.Errorf("%s: reserved byte is not zero", op))
	}

	funcIndex := popOperand(f, wa.I32)

	opSaveOperands(f)

	var funcIndexReg reg.R
	if funcIndex.Storage == storage.Reg {
		funcIndexReg = funcIndex.Reg()
	} else {
		funcIndexReg = reg.Result
		asm.Move(f, funcIndexReg, funcIndex)
	}

	sig := f.Module.Types[sigIndex]
	checkCallOperandCount(f, sig)
	opCallIndirect(f, int32(sigIndex), funcIndexReg)

	// The called function's initial suspension point was certainly executed.
	if len(f.BranchTargets) > 0 {
		getCurrentBlock(f).Suspension = true
	}

	opFinalizeCall(f, sig)
}

func checkCallOperandCount(f *gen.Func, sig wa.FuncType) {
	if debug.Enabled {
		debug.Printf("sig: %s", sig)
	}

	oper := len(f.Operands) - 1

	for param := len(sig.Params) - 1; param >= 0; param-- {
		if oper < f.FrameBase {
			pan.Panic(errCallParamsExceedStack)
		}

		x := f.Operands[oper]
		oper--

		if x.Storage == storage.Unreachable {
			return // All good.
		}

		if x.Type != sig.Params[param] {
			pan.Panic(errCallParamTypeMismatch)
		}
	}
}

func opFinalizeCall(f *gen.Func, sig wa.FuncType) {
	f.Regs.CheckNoneAllocated()

	opDropCallOperands(f, len(sig.Params))

	if len(sig.Results) > 0 {
		pushResultRegOperand(f, sig.Results[0])
	}
}

func opCall(f *gen.Func, l *link.L) {
	if l.Addr != 0 {
		asm.Call(&f.Prog, l.Addr)
	} else {
		asm.CallMissing(&f.Prog, f.AtomicCallStubs)
	}
	f.MapCallAddr(f.Text.Addr)
	if l.Addr == 0 {
		l.AddSite(f.Text.Addr)
	}
}

func opCallIndirect(f *gen.Func, sigIndex int32, funcIndexReg reg.R) {
	asm.CallIndirect(f, sigIndex, funcIndexReg)
	f.MapCallAddr(f.Text.Addr)
}

func opCallMemoryRoutine(f *gen.Func, load *loader.L, op opcode.MiscOpcode, routineAddr int32) {
	if !f.Module.Memory {
		pan.Panic(errUnknownMemory)
	}

	opSaveOperands(f)

	if len(f.Operands)-f.FrameBase < 3 {
		pan.Panic(module.Errorf("%s parameter count exceeds stack operand count", op))
	}
	for i := len(f.Operands) - 3; i < len(f.Operands); i++ {
		if f.Operands[i].Type != wa.I32 {
			pan.Panic(module.Errorf("%s argument has wrong type", op))
		}
	}

	asm.Call(&f.Prog, routineAddr)
	f.MapCallAddr(f.Text.Addr)

	opDropCallOperands(f, 3)
}
