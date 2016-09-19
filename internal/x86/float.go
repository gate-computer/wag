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

func (p *floatSizePrefix) writeTo(code gen.Coder, t types.T, ro, index, rmOrBase regs.R) {
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
	operandSize = &floatSizePrefix{nil, []byte{0x66}}
	scalarSize  = &floatSizePrefix{[]byte{0xf3}, []byte{0xf2}}
)

var (
	UcomissUcomisd = insnPrefixModRegFromReg{operandSize, []byte{0x0f, 0x2e}}
	AddssAddsd     = insnPrefixModRegFromReg{scalarSize, []byte{0x0f, 0x58}}
	SubssSubsd     = insnPrefixModRegFromReg{scalarSize, []byte{0x0f, 0x5c}}
	DivssDivsd     = insnPrefixModRegFromReg{scalarSize, []byte{0x0f, 0x5e}}

	MovssMovsd = insnPrefixModRegToReg{scalarSize, []byte{0x0f, 0x11}, ModReg}
	XorpsXorpd = insnPrefixModRegToReg{operandSize, []byte{0x0f, 0x57}, ModReg}

	MovssMovsdFromIndirect = insnPrefixModRegFromRegDisp{scalarSize, []byte{0x0f, 0x10}}

	MovssMovsdFromStack = insnPrefixModRegSibImm{scalarSize, []byte{0x0f, 0x10}, sib{0, regStackPtr, regStackPtr}}
	MovssMovsdToStack   = insnPrefixModRegSibImm{scalarSize, []byte{0x0f, 0x11}, sib{0, regStackPtr, regStackPtr}}
)

var binaryFloatInsns = map[string]binaryRegInsn{
	"add": AddssAddsd,
	"div": DivssDivsd,
	"sub": SubssSubsd,
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

		MovssMovsd.op(code, t, regScratch, targetReg)
		SubssSubsd.opReg(code, t, targetReg, regScratch)
		SubssSubsd.opReg(code, t, targetReg, regScratch)
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

		insn.opReg(code, t, targetReg, sourceReg)
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

		UcomissUcomisd.opReg(code, t, aReg, bReg)
		return values.ConditionFlagsOperand(cond)
	}

	panic(name)
}

func pushFloatOp(code gen.Coder, t types.T, source regs.R) {
	SubImm.op(code, types.I64, regStackPtr, wordSize)
	MovssMovsdToStack.op(code, t, source, 0)
}

func popFloatOp(code gen.Coder, t types.T, target regs.R) {
	MovssMovsdFromStack.op(code, t, target, 0)
	AddImm.op(code, types.I64, regStackPtr, wordSize)
}
