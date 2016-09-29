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
	Const66RexSize = multiPrefix{constPrefix{0x66}, RexSize}
	OperandSize    = &floatSizePrefix{nil, []byte{0x66}}
	ScalarSize     = &floatSizePrefix{[]byte{0xf3}, []byte{0xf2}}
	RoundSize      = &floatSizePrefix{[]byte{0x0a}, []byte{0x0b}}
)

var (
	UcomisSSE = insnPrefix{OperandSize, []byte{0x0f, 0x2e}, nil}
	XorpSSE   = insnPrefix{OperandSize, []byte{0x0f, 0x57}, nil}
	MovSSE    = insnPrefix{Const66RexSize, []byte{0x0f, 0x6e}, []byte{0x0f, 0x7e}}
	PxorSSE   = insnPrefix{Const66RexSize, []byte{0x0f, 0xef}, nil}
	MovsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x10}, []byte{0x0f, 0x11}}
	SqrtsSSE  = insnPrefix{ScalarSize, []byte{0x0f, 0x51}, nil}
	AddsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x58}, nil}
	MulsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x59}, nil}
	Cvts2sSSE = insnPrefix{ScalarSize, []byte{0x0f, 0x5a}, nil} // convert float to float
	SubsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5c}, nil}
	MinsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5d}, nil}
	DivsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5e}, nil}
	MaxsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5f}, nil}

	Cvtsi2sSSE  = insnPrefixRexRM{ScalarSize, []byte{0x0f, 0x2a}}
	CvttsSSE2si = insnPrefixRexRM{ScalarSize, []byte{0x0f, 0x2c}}

	RoundsSSE = insnSuffixRMI{[]byte{0x66, 0x0f, 0x3a}, RoundSize}
)

const (
	floatRoundNearest  = 0x0
	floatRoundDown     = 0x1
	floatRoundUp       = 0x2
	floatRoundTruncate = 0x3
)

var unaryFloatInsns = map[string]insnPrefix{
	"sqrt": SqrtsSSE,
}

var unaryFloatRoundModes = map[string]int8{
	"ceil":    floatRoundUp,
	"floor":   floatRoundDown,
	"nearest": floatRoundNearest,
	"trunc":   floatRoundTruncate,
}

var binaryFloatInsns = map[string]insnPrefix{
	"add": AddsSSE,
	"div": DivsSSE,
	"max": MaxsSSE,
	"min": MinsSSE,
	"mul": MulsSSE,
	"sub": SubsSSE,
}

var binaryFloatConditions = map[string]values.Condition{
	"eq": values.OrderedAndEQ,
	"ge": values.OrderedAndGE,
	"gt": values.OrderedAndGT,
	"le": values.OrderedAndLE,
	"lt": values.OrderedAndLT,
	"ne": values.UnorderedOrNE,
}

// TODO: support memory source operands

func (mach X86) unaryFloatOp(code gen.RegCoder, name string, t types.T, x values.Operand) values.Operand {
	switch name {
	case "neg":
		targetReg, _ := mach.opMaybeResultReg(code, t, x, false)

		signMask := int64(-1) << (uint(t.Size())*8 - 1)

		MovImm64.op(code, t, regScratch, signMask)        // integer scratch register
		MovSSE.opFromReg(code, t, regScratch, regScratch) // float scratch register
		XorpSSE.opFromReg(code, t, targetReg, regScratch)

		return values.TempRegOperand(targetReg, false)
	}

	if mode, found := unaryFloatRoundModes[name]; found {
		reg, _ := mach.opMaybeResultReg(code, t, x, false)
		RoundsSSE.opReg(code, t, reg, reg, mode)
		return values.TempRegOperand(reg, false)
	}

	if insn, found := unaryFloatInsns[name]; found {
		reg, _ := mach.opMaybeResultReg(code, t, x, false)
		insn.opFromReg(code, t, reg, reg)
		return values.TempRegOperand(reg, false)
	}

	panic(name)
}

func (mach X86) binaryFloatOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	if insn, found := binaryFloatInsns[name]; found {
		targetReg, _ := mach.opMaybeResultReg(code, t, a, false)

		sourceReg, _, own := mach.opBorrowMaybeScratchReg(code, t, b, false)
		if own {
			defer code.FreeReg(t, sourceReg)
		}

		insn.opFromReg(code, t, targetReg, sourceReg)
		return values.TempRegOperand(targetReg, false)
	}

	if cond, found := binaryFloatConditions[name]; found {
		aReg, _, own := mach.opBorrowMaybeResultReg(code, t, a, true)
		if own {
			defer code.FreeReg(t, aReg)
		}

		bReg, _, own := mach.opBorrowMaybeScratchReg(code, t, b, false)
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
