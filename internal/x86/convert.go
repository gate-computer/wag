package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

func (mach X86) ConversionOp(code gen.RegCoder, name string, resultType, t types.T, x values.Operand) values.Operand {
	reg, _, own := mach.opBorrowScratchReg(code, t, x)
	if own {
		defer code.FreeReg(t, reg)
	}

	switch name {
	case "f32.convert_s/i32", "f32.convert_s/i64":
		Cvtsi2ssSSE.opFromReg(code, t, regResult, reg)

	case "f64.convert_s/i32", "f64.convert_s/i64":
		Cvtsi2sdSSE.opFromReg(code, t, regResult, reg)

	case "i64.extend_s/i32":
		Movsxd.opFromReg(code, t, regResult, reg)

	case "f32.reinterpret/i32", "f64.reinterpret/i64":
		MovSSE.opFromReg(code, t, regResult, reg)

	case "i32.reinterpret/f32", "i64.reinterpret/f64":
		MovSSE.opToReg(code, t, regResult, reg)

	default:
		panic(name)
	}

	return values.TempRegOperand(regResult, values.NoExt)
}
