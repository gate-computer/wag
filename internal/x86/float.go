package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

type floatPrefix struct {
	size32 []byte
	size64 []byte
}

func (p *floatPrefix) writeTo(code *gen.Coder, t types.T, dummy regs.R) {
	switch t.Size() {
	case types.Size32:
		code.Write(p.size32)

	case types.Size64:
		code.Write(p.size64)

	default:
		panic(t)
	}
}

var (
	operandSize = &floatPrefix{nil, []byte{0x66}}
	scalarSize  = &floatPrefix{[]byte{0xf3}, []byte{0xf2}}
)

var (
	UcomissUcomisd = insnPrefixModRegFromReg{operandSize, []byte{0x0f, 0x2e}, ModReg}
	AddssAddsd     = insnPrefixModRegFromReg{scalarSize, []byte{0x0f, 0x58}, ModReg}
	SubssSubsd     = insnPrefixModRegFromReg{scalarSize, []byte{0x0f, 0x5c}, ModReg}
	DivssDivsd     = insnPrefixModRegFromReg{scalarSize, []byte{0x0f, 0x5e}, ModReg}

	MovssMovsd = insnPrefixModRegToReg{scalarSize, []byte{0x0f, 0x11}, ModReg}

	MovssMovsdFromIndirect = insnPrefixModRegFromRegDisp{scalarSize, []byte{0x0f, 0x10}}

	MovssMovsdFromStack = insnPrefixModRegSibImm{scalarSize, []byte{0x0f, 0x10}, sib{0, regStackPtr, regStackPtr}}
	MovssMovsdToStack   = insnPrefixModRegSibImm{scalarSize, []byte{0x0f, 0x11}, sib{0, regStackPtr, regStackPtr}}
)

var binaryFloatInsns = map[string]binaryInsn{
	"add": AddssAddsd,
	"div": DivssDivsd,
	"sub": SubssSubsd,
}

var setccFloatInsns = map[string]unaryInsn{
	"eq": Sete,
	"gt": Setg,
	"ne": Setne,
	"lt": Setl,
}

func (x86 X86) unaryFloatOp(code *gen.Coder, name string, t types.T, source values.Operand) {
	x86.getRegOperandIn(code, t, regs.R0, source)

	switch name {
	case "neg":
		MovssMovsd.op(code, t, regScratch, regs.R0)
		SubssSubsd.op(code, t, regs.R0, regScratch)
		SubssSubsd.op(code, t, regs.R0, regScratch)
		return
	}

	panic(name)
}

func (x86 X86) binaryFloatOp(code *gen.Coder, name string, t types.T, source values.Operand) {
	sourceReg := x86.getTempRegOperand(code, t, source)

	if insn, found := binaryFloatInsns[name]; found {
		insn.op(code, t, regs.R0, sourceReg)
		return
	}

	if setcc, found := setccFloatInsns[name]; found {
		UcomissUcomisd.op(code, t, regs.R0, sourceReg)
		setcc.op(code, regs.R0)
		Movzx8.op(code, regs.R0, regs.R0)
		return
	}

	panic(name)
}

func pushFloatOp(code *gen.Coder, t types.T, source regs.R) {
	SubImm.op(code, types.I64, regStackPtr, wordSize)
	MovssMovsdToStack.op(code, t, source, 0)
}

func popFloatOp(code *gen.Coder, t types.T, target regs.R) {
	MovssMovsdFromStack.op(code, t, target, 0)
	AddImm.op(code, types.I64, regStackPtr, wordSize)
}
