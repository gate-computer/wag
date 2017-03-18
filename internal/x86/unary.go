package x86

import (
	"errors"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/opers"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
)

func (mach X86) UnaryOp(code gen.RegCoder, oper uint16, x values.Operand) values.Operand {
	if (oper & opers.UnaryFloat) == 0 {
		return mach.unaryIntOp(code, uint8(oper), x)
	} else {
		return mach.unaryFloatOp(code, oper, x)
	}
}

func (mach X86) unaryIntOp(code gen.RegCoder, index uint8, x values.Operand) (result values.Operand) {
	switch index {
	case opers.IndexIntEqz:
		reg, _, own := mach.opBorrowMaybeScratchReg(code, x, false)
		if own {
			defer code.FreeReg(x.Type, reg)
		}

		Test.opFromReg(code, x.Type, reg, reg)
		result = values.ConditionFlagsOperand(values.Eq)

	default:
		var targetReg regs.R

		sourceReg, _, own := mach.opBorrowMaybeScratchReg(code, x, false)
		if own {
			targetReg = sourceReg
		} else {
			var ok bool

			targetReg, ok = code.TryAllocReg(x.Type)
			if !ok {
				targetReg = regResult
			}
		}

		result = values.TempRegOperand(x.Type, targetReg, true)

		switch index {
		case opers.IndexIntClz:
			Bsr.opFromReg(code, x.Type, regScratch, sourceReg)
			MovImm.opImm(code, x.Type, targetReg, -1)
			Cmove.opFromReg(code, x.Type, regScratch, targetReg)
			MovImm.opImm(code, x.Type, targetReg, (int32(x.Type.Size())<<3)-1)
			Sub.opFromReg(code, x.Type, targetReg, regScratch)

		case opers.IndexIntCtz:
			Bsf.opFromReg(code, x.Type, targetReg, sourceReg)
			MovImm.opImm(code, x.Type, regScratch, int32(x.Type.Size())<<3)
			Cmove.opFromReg(code, x.Type, targetReg, regScratch)

		case opers.IndexIntPopcnt:
			Popcnt.opFromReg(code, x.Type, targetReg, sourceReg)
		}
	}

	return
}

var unaryFloatInsns = []insnPrefix{
	opers.IndexFloatSqrt:     SqrtsSSE,
	opers.IndexFloatAbs:      {},
	opers.IndexFloatCopysign: {},
}

func (mach X86) unaryFloatOp(code gen.RegCoder, oper uint16, x values.Operand) (result values.Operand) {
	// TODO: support memory source operands

	reg, _ := mach.opMaybeResultReg(code, x, false)
	result = values.TempRegOperand(x.Type, reg, false)

	switch {
	case (oper & opers.UnaryRound) != 0:
		mode := uint8(oper)
		RoundsSSE.opReg(code, x.Type, reg, reg, int8(mode))

	case oper == opers.FloatNeg:
		signMask := int64(-1) << (uint(x.Type.Size())*8 - 1)
		MovImm64.op(code, x.Type, regScratch, signMask)        // integer scratch register
		MovSSE.opFromReg(code, x.Type, regScratch, regScratch) // float scratch register
		XorpSSE.opFromReg(code, x.Type, reg, regScratch)

	default:
		index := uint8(oper)
		insn := unaryFloatInsns[index]

		// TODO: remove this check after abs and copysign have been implemented
		if insn.prefix == nil {
			panic(errors.New("opcode not implemented"))
		}

		insn.opFromReg(code, x.Type, reg, reg)
	}

	return
}
