package x86

import (
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

const (
	rexB = (1 << 6) | (1 << 2)
	rexW = (1 << 6) | (1 << 3)
)

type rexPrefix struct{}

func (rexPrefix) writeTo(code *Coder, t types.T, ro regs.R) {
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

	Mul = insnPrefixModOpRegRax{rex, []byte{0xf7}, 4}
	Div = insnPrefixModOpRegRax{rex, []byte{0xf7}, 6}

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

func unaryIntOp(code *Coder, name string, t types.T) {
	switch name {
	case "ctz":
		Bsf.op(code, t, regs.R0, regs.R0)

	case "eqz":
		Test.op(code, t, regs.R0, regs.R0)
		Sete.op(code, regs.R0)
		Movzx8.op(code, regs.R0, regs.R0)

	default:
		panic(name)
	}
}

func binaryIntOp(code *Coder, name string, t types.T) {
	if insn, found := binaryIntInsns[name]; found {
		insn.op(code, t, regs.R0, regs.R1)
		return
	}

	if setcc, found := setccIntInsns[name]; found {
		Cmp.op(code, t, regs.R0, regs.R1)
		setcc.op(code, regs.R0)
		Movzx8.op(code, regs.R0, regs.R0)
		return
	}

	switch name {
	case "div_u":
		Test.op(code, t, regs.R1, regs.R1)
		Je.op(code)
		code.divideByZero.Sites = append(code.divideByZero.Sites, code.Len())
		Xor.op(code, t, regScratch, regScratch)
		Div.op(code, t, regs.R1)

	case "mul":
		Mul.op(code, t, regs.R1)

	default:
		panic(name)
	}
}
