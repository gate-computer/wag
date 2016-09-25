package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

func (mach X86) ConversionOp(code gen.RegCoder, name string, resultType, t types.T, x values.Operand) values.Operand {
	switch name {
	case "i32.wrap/i64":
		if reg, zeroExt, ok := x.CheckTempReg(); ok && zeroExt {
			return values.TempRegOperand(reg, false)
		} else {
			return x
		}
	}

	reg, _, own := mach.opBorrowMaybeScratchReg(code, t, x, false)
	if own {
		defer code.FreeReg(t, reg)
	}

	zeroExt := false

	switch name {
	case "f32.convert_s/i32", "f32.convert_s/i64":
		Cvtsi2ssSSE.opFromReg(code, t, regResult, reg)

	case "f64.convert_s/i32", "f64.convert_s/i64":
		Cvtsi2sdSSE.opFromReg(code, t, regResult, reg)

	case "i64.extend_s/i32":
		Movsxd.opFromReg(code, 0, regResult, reg)

	case "i64.extend_u/i32":
		Mov.opFromReg(code, t, regResult, reg)

	case "f32.reinterpret/i32", "f64.reinterpret/i64":
		MovSSE.opFromReg(code, t, regResult, reg)

	case "i32.reinterpret/f32", "i64.reinterpret/f64":
		MovSSE.opToReg(code, t, regResult, reg)
		zeroExt = true

	default:
		panic(name)
	}

	return values.TempRegOperand(regResult, zeroExt)
}
