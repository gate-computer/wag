package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

type floatSizePrefix struct {
	size32 []byte
	size64 []byte
}

func (p *floatSizePrefix) writeTo(code gen.Coder, t types.T, ro, index, rmOrBase byte) {
	switch t.Size() {
	case types.Size32:
		code.Write(p.size32)

	case types.Size64:
		code.Write(p.size64)

	default:
		panic(t)
	}

	writeRexTo(code, 0, ro, index, rmOrBase)
}

var (
	OperandSize = &floatSizePrefix{nil, []byte{0x66}}
	ScalarSize  = &floatSizePrefix{[]byte{0xf3}, []byte{0xf2}}
)

var (
	UcomisSSE = insnPrefix{OperandSize, []byte{0x0f, 0x2e}, nil}
	XorpSSE   = insnPrefix{OperandSize, []byte{0x0f, 0x57}, nil}
	MovsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x10}, []byte{0x0f, 0x11}}
	AddsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x58}, nil}
	SubsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5c}, nil}
	DivsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5e}, nil}
)

var binaryFloatInsns = map[string]insnPrefix{
	"add": AddsSSE,
	"div": DivsSSE,
	"sub": SubsSSE,
}

var binaryFloatConditions = map[string]values.Condition{
	"eq": values.EQ,
	"gt": values.GT_S,
	"lt": values.LT_S,
	"ne": values.NE,
}

func (mach X86) unaryFloatOp(code gen.RegCoder, name string, t types.T, x values.Operand) values.Operand {
	switch name {
	case "neg":
		targetReg := mach.opResultReg(code, t, x)

		MovsSSE.opFromReg(code, t, regScratch, targetReg)
		SubsSSE.opFromReg(code, t, targetReg, regScratch)
		SubsSSE.opFromReg(code, t, targetReg, regScratch)
		return values.TempRegOperand(targetReg)
	}

	panic(name)
}

func (mach X86) binaryFloatOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	if insn, found := binaryFloatInsns[name]; found {
		targetReg := mach.opResultReg(code, t, a)

		sourceReg, own := mach.opBorrowScratchReg(code, t, b)
		if own {
			defer code.FreeReg(t, sourceReg)
		}

		insn.opFromReg(code, t, targetReg, sourceReg)
		return values.TempRegOperand(targetReg)
	}

	if cond, found := binaryFloatConditions[name]; found {
		aReg, own := mach.opBorrowResultReg(code, t, a)
		if own {
			defer code.FreeReg(t, aReg)
		}

		bReg, own := mach.opBorrowScratchReg(code, t, b)
		if own {
			defer code.FreeReg(t, bReg)
		}

		UcomisSSE.opFromReg(code, t, aReg, bReg)
		return values.ConditionFlagsOperand(cond)
	}

	panic(name)
}

func pushFloatOp(code gen.Coder, t types.T, source regs.R) {
	Sub.opImm(code, types.I64, regStackPtr, wordSize)
	MovsSSE.opToStack(code, t, source, 0)
}

func popFloatOp(code gen.Coder, t types.T, target regs.R) {
	MovsSSE.opFromStack(code, t, target, 0)
	Add.opImm(code, types.I64, regStackPtr, wordSize)
}
