package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

const (
	rexB = (1 << 6) | (1 << 2)
	rexW = (1 << 6) | (1 << 3)
)

type rexPrefix struct{}

func (rexPrefix) writeTo(code *gen.Coder, t types.T, ro regs.R) {
	var rex byte

	if ro >= 8 {
		rex |= rexB
	}

	switch t.Size() {
	case types.Size32:

	case types.Size64:
		rex |= rexW

	default:
		panic(t)
	}

	if rex != 0 {
		code.WriteByte(rex)
	}
}

var (
	rex rexPrefix
)

var (
	Movzx8 = insnModRegFromReg{0x0f, 0xb6}

	MovImm = insnPrefixRegImm{rex, 0xb8}

	Mul = insnPrefixModOpReg{rex, []byte{0xf7}, 4}
	Div = insnPrefixModOpReg{rex, []byte{0xf7}, 6}
	Inc = insnPrefixModOpReg{rex, []byte{0xff}, 0}
	Dec = insnPrefixModOpReg{rex, []byte{0xff}, 1}

	Bsf    = insnPrefixModRegFromReg{rex, []byte{0x0f, 0xbc}, ModReg}
	Movsxd = insnPrefixModRegFromReg{rex, []byte{0x63}, ModReg}

	Add   = insnPrefixModRegToReg{rex, []byte{0x01}, ModReg}
	Or    = insnPrefixModRegToReg{rex, []byte{0x09}, ModReg}
	And   = insnPrefixModRegToReg{rex, []byte{0x21}, ModReg}
	Sub   = insnPrefixModRegToReg{rex, []byte{0x29}, ModReg}
	Xor   = insnPrefixModRegToReg{rex, []byte{0x31}, ModReg}
	Cmp   = insnPrefixModRegToReg{rex, []byte{0x39}, ModReg}
	Test  = insnPrefixModRegToReg{rex, []byte{0x85}, ModReg}
	Mov   = insnPrefixModRegToReg{rex, []byte{0x89}, ModReg}
	Cmovl = insnPrefixModRegToReg{rex, []byte{0x0f, 0x4c}, ModReg}

	ShlImm = insnPrefixModOpRegImm{rex, []byte{0xc1}, 0}
	ShrImm = insnPrefixModOpRegImm{rex, []byte{0xc1}, 5}

	MovsxdFromStack = insnPrefixModRegSibImm{rex, []byte{0x63}, sib{0, regStackPtr, regStackPtr}}
	MovToStack      = insnPrefixModRegSibImm{rex, []byte{0x89}, sib{0, regStackPtr, regStackPtr}}
	MovFromStack    = insnPrefixModRegSibImm{rex, []byte{0x8b}, sib{0, regStackPtr, regStackPtr}}

	MovsxdFromIndirectScaleIndex = insnPrefixModRegCustomSibImm{rex, []byte{0x63}}
	MovFromIndirectScaleIndex    = insnPrefixModRegCustomSibImm{rex, []byte{0x8b}}

	AddImm = insnPrefixArithmeticModOpRegImm{rex, 0}
	SubImm = insnPrefixArithmeticModOpRegImm{rex, 5}
	CmpImm = insnPrefixArithmeticModOpRegImm{rex, 7}
)

var binaryIntInsns = map[string]binaryInsn{
	"add": Add,
	"and": And,
	"or":  Or,
	"sub": Sub,
	"xor": Xor,
}

var setccIntInsns = map[string]unaryInsn{
	"eq":   Sete,
	"gt_s": Setg,
	"gt_u": Seta,
	"lt_s": Setl,
	"ne":   Setne,
}

func (x86 X86) unaryIntOp(code *gen.Coder, name string, t types.T, source values.Operand) values.Operand {
	value, immediate := source.CheckImmValue(t)

	switch name {
	case "ctz":
		x86.getRegOperandIn(code, t, regs.R0, source)
		Bsf.op(code, t, regs.R0, regs.R0)
		return values.RegOperand(regs.R0)

	case "eqz":
		if immediate {
			if value == 0 {
				return values.ImmOperand(types.I32, 1)
			} else {
				return values.ImmOperand(types.I32, 0)
			}
		}

		sourceReg := x86.getTempRegOperand(code, t, source)
		Test.op(code, t, sourceReg, sourceReg)
		Sete.op(code, regs.R0)
		Movzx8.op(code, regs.R0, regs.R0)
		return values.RegOperand(regs.R0)
	}

	panic(name)
}

func (x86 X86) binaryIntOp(code *gen.Coder, name string, t types.T, source values.Operand) values.Operand {
	value, immediate := source.CheckImmValue(t)

	if immediate && value == 0 {
		switch name {
		case "add", "or", "sub":
			return source

		case "mul":
			return values.ImmOperand(t, 0)
		}
	}

	switch name {
	case "add":
		if immediate {
			switch value {
			case 1:
				Inc.op(code, t, regs.R0)
				return values.RegOperand(regs.R0)

			case -1:
				Dec.op(code, t, regs.R0)
				return values.RegOperand(regs.R0)
			}
		}

	case "sub":
		if immediate {
			switch value {
			case 1:
				Dec.op(code, t, regs.R0)
				return values.RegOperand(regs.R0)

			case -1:
				Inc.op(code, t, regs.R0)
				return values.RegOperand(regs.R0)
			}
		}

	case "div_u":
		if immediate && value > 0 && isPowerOfTwo(uint64(value)) {
			ShrImm.op(code, t, regs.R0, uimm8(log2(uint64(value))))
		} else {
			sourceReg := x86.getTempRegOperand(code, t, source)
			Test.op(code, t, sourceReg, sourceReg)
			Je.op(code)
			code.TrapDivideByZero.AddSite(code.Len())
			Xor.op(code, t, regDividendHi, regDividendHi)
			Div.op(code, t, sourceReg)
		}
		return values.RegOperand(regs.R0)

	case "mul":
		if immediate && value > 0 && isPowerOfTwo(uint64(value)) {
			ShlImm.op(code, t, regs.R0, uimm8(log2(uint64(value))))
		} else {
			sourceReg := x86.getTempRegOperand(code, t, source)
			Mul.op(code, t, sourceReg)
		}
		return values.RegOperand(regs.R0)
	}

	if insn, found := binaryIntInsns[name]; found {
		sourceReg := x86.getTempRegOperand(code, t, source)
		insn.op(code, t, regs.R0, sourceReg)
		return values.RegOperand(regs.R0)
	}

	if setcc, found := setccIntInsns[name]; found {
		sourceReg := x86.getTempRegOperand(code, t, source)
		Cmp.op(code, t, regs.R0, sourceReg)
		setcc.op(code, regs.R0)
		Movzx8.op(code, regs.R0, regs.R0)
		return values.RegOperand(regs.R0)
	}

	panic(name)
}

func isPowerOfTwo(value uint64) bool {
	return (value & (value - 1)) == 0
}

// log2 assumes that value isPowerOfTwo.
func log2(value uint64) (count int) {
	for {
		value >>= 1
		if value == 0 {
			return
		}
		count++
	}
}
