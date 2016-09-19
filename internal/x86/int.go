package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

type rexSizePrefix struct{}

func (rexSizePrefix) writeTo(code gen.Coder, t types.T, ro, index, rmOrBase regs.R) {
	var rex byte

	switch t.Size() {
	case types.Size32:

	case types.Size64:
		rex |= rexW

	default:
		panic(t)
	}

	writeRexTo(code, rex, ro, index, rmOrBase)
}

var (
	rexSize rexSizePrefix
)

var (
	Movzx8 = insnModRegFromReg{0x0f, 0xb6}

	MovImm = insnPrefixRegImm{rexSize, 0xb8}

	Neg = insnPrefixModOpReg{rexSize, []byte{0xf7}, 3}
	Mul = insnPrefixModOpReg{rexSize, []byte{0xf7}, 4}
	Div = insnPrefixModOpReg{rexSize, []byte{0xf7}, 6}
	Inc = insnPrefixModOpReg{rexSize, []byte{0xff}, 0}
	Dec = insnPrefixModOpReg{rexSize, []byte{0xff}, 1}

	Push = insnReg_sizeless_PrefixModOpReg{insnReg{0x50}, insnPrefixModOpReg{rexSize, []byte{0xff}, 6}}
	Pop  = insnReg_sizeless_PrefixModOpReg{insnReg{0x58}, insnPrefixModOpReg{rexSize, []byte{0x8f}, 0}}

	Add    = insnPrefixModRegFromReg{rexSize, []byte{0x03}}
	Or     = insnPrefixModRegFromReg{rexSize, []byte{0x0b}}
	And    = insnPrefixModRegFromReg{rexSize, []byte{0x23}}
	Sub    = insnPrefixModRegFromReg{rexSize, []byte{0x2b}}
	Xor    = insnPrefixModRegFromReg{rexSize, []byte{0x33}}
	Cmp    = insnPrefixModRegFromReg{rexSize, []byte{0x3b}}
	Movsxd = insnPrefixModRegFromReg{rexSize, []byte{0x63}}
	Cmovl  = insnPrefixModRegFromReg{rexSize, []byte{0x0f, 0x4c}}
	Bsf    = insnPrefixModRegFromReg{rexSize, []byte{0x0f, 0xbc}}

	Test = insnPrefixModRegToReg{rexSize, []byte{0x85}, ModReg}
	Mov  = insnPrefixModRegToReg{rexSize, []byte{0x89}, ModReg}

	CmpImm32 = insnPrefixModOpRegImm{rexSize, []byte{0x81}, 7}
	ShlImm   = insnPrefixModOpRegImm{rexSize, []byte{0xc1}, 0}
	ShrImm   = insnPrefixModOpRegImm{rexSize, []byte{0xc1}, 5}
	MovImm32 = insnPrefixModOpRegImm{rexSize, []byte{0xc7}, 0}

	CmpFromStack    = insnPrefixModRegSibImm{rexSize, []byte{0x3b}, sib{0, regStackPtr, regStackPtr}}
	MovsxdFromStack = insnPrefixModRegSibImm{rexSize, []byte{0x63}, sib{0, regStackPtr, regStackPtr}}
	MovToStack      = insnPrefixModRegSibImm{rexSize, []byte{0x89}, sib{0, regStackPtr, regStackPtr}}
	MovFromStack    = insnPrefixModRegSibImm{rexSize, []byte{0x8b}, sib{0, regStackPtr, regStackPtr}}

	MovsxdFromIndirectScaleIndex = insnPrefixModRegCustomSibImm{rexSize, []byte{0x63}}
	MovFromIndirectScaleIndex    = insnPrefixModRegCustomSibImm{rexSize, []byte{0x8b}}

	AddImm = insnPrefixArithmeticModOpRegImm{rexSize, 0}
	OrImm  = insnPrefixArithmeticModOpRegImm{rexSize, 1}
	AndImm = insnPrefixArithmeticModOpRegImm{rexSize, 4}
	SubImm = insnPrefixArithmeticModOpRegImm{rexSize, 5}
	XorImm = insnPrefixArithmeticModOpRegImm{rexSize, 6}
	CmpImm = insnPrefixArithmeticModOpRegImm{rexSize, 7}
)

var binaryIntInsns = map[string]binaryInsn{
	"add": binaryInsn{Add, AddImm},
	"and": binaryInsn{And, AndImm},
	"or":  binaryInsn{Or, OrImm},
	"sub": binaryInsn{Sub, SubImm},
	"xor": binaryInsn{Xor, XorImm},
}

var binaryIntDivMulInsns = map[string]binaryIntDivMulInsn{
	"div_u": binaryIntDivMulInsn{Div, ShrImm},
	"mul":   binaryIntDivMulInsn{Mul, ShlImm},
}

var binaryIntConditions = map[string]values.Condition{
	"eq":   values.EQ,
	"gt_s": values.GT_S,
	"gt_u": values.GT_U,
	"lt_s": values.LT_S,
	"ne":   values.NE,
}

func (mach X86) unaryIntOp(code gen.RegCoder, name string, t types.T, x values.Operand) values.Operand {
	switch name {
	case "ctz":
		var targetReg regs.R

		sourceReg, own := mach.opBorrowScratchReg(code, t, x)
		if own {
			targetReg = sourceReg
		} else {
			targetReg = mach.opResultReg(code, t, values.NoOperand)
		}

		Bsf.opReg(code, t, targetReg, sourceReg)
		return values.TempRegOperand(targetReg)

	case "eqz":
		reg, own := mach.opBorrowScratchReg(code, t, x)
		if own {
			defer code.FreeReg(t, reg)
		}

		Test.op(code, t, reg, reg)
		return values.ConditionFlagsOperand(values.EQ)
	}

	panic(name)
}

func (mach X86) binaryIntOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	switch a.Storage {
	case values.Stack, values.ConditionFlags:
		panic(a)
	}

	switch name {
	case "div_u", "mul":
		return mach.binaryIntDivMulOp(code, name, t, a, b)

	default:
		return mach.binaryIntGenericOp(code, name, t, a, b)
	}
}

func (mach X86) binaryIntGenericOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	if value, ok := a.CheckImmValue(t); ok {
		switch {
		case value == 0 && name == "sub":
			reg := mach.opResultReg(code, t, b)
			Neg.opReg(code, t, reg)
			return values.TempRegOperand(reg)
		}
	}

	switch b.Storage {
	case values.Imm:
		value := b.ImmValue(t)

		switch {
		case (name == "add" && value == 1) || (name == "sub" && value == -1):
			reg := mach.opResultReg(code, t, a)
			Inc.opReg(code, t, reg)
			return values.TempRegOperand(reg)

		case (name == "sub" && value == 1) || (name == "add" && value == -1):
			reg := mach.opResultReg(code, t, a)
			Dec.opReg(code, t, reg)
			return values.TempRegOperand(reg)

		case value < -0x80000000 || value >= 0x80000000:
			reg, own := mach.opBorrowScratchReg(code, t, b)
			b = values.RegOperand(reg, own)
		}

	case values.Stack, values.ConditionFlags:
		reg, own := mach.opBorrowScratchReg(code, t, b)
		b = values.RegOperand(reg, own)
	}

	if insn, found := binaryIntInsns[name]; found {
		reg := mach.opResultReg(code, t, a)
		insn.op(code, t, reg, b)
		return values.TempRegOperand(reg)
	} else if cond, found := binaryIntConditions[name]; found {
		reg, own := mach.opBorrowResultReg(code, t, a)
		if own {
			defer code.FreeReg(t, reg)
		}

		switch b.Storage {
		case values.Imm:
			CmpImm32.op(code, t, reg, imm32(int(b.ImmValue(t))))

		case values.ROData:
			Cmp.opFromAddr(code, t, reg, code.RODataAddr()+b.Addr())

		case values.VarMem:
			CmpFromStack.op(code, t, reg, b.Offset())

		case values.VarReg, values.TempReg, values.BorrowedReg:
			Cmp.opReg(code, t, reg, b.Reg())

		default:
			panic(b)
		}

		code.Consumed(t, b)

		return values.ConditionFlagsOperand(cond)
	}

	panic(name)
}

func (mach X86) binaryIntDivMulOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	insn := binaryIntDivMulInsns[name]

	if value, ok := b.CheckImmValue(t); ok {
		switch {
		case value == -1:
			reg := mach.opResultReg(code, t, a)
			Neg.opReg(code, t, reg)
			return values.TempRegOperand(reg)

		case value > 0 && isPowerOfTwo(uint64(value)):
			reg := mach.opResultReg(code, t, a)
			insn.shiftImm.op(code, t, reg, uimm8(log2(uint64(value))))
			return values.TempRegOperand(reg)
		}
	}

	bStorage := b.Storage
	bReg, ok := b.CheckAnyReg()
	if ok {
		if name == "div_u" {
			Test.op(code, t, bReg, bReg)
			Je.op(code, code.TrapLinks().DivideByZero.FinalAddress())
		}

		if bReg == regResult {
			bStorage = values.TempReg

			switch name {
			case "div_u":
				// can't use scratch reg as divisor since it contains the dividend high bits
				bReg, ok = code.TryAllocReg(t)
				if ok {
					defer code.FreeReg(t, bReg)
				} else {
					bReg = regTextPtr

					code.AddStackUsage(wordSize)
					MovToStack.op(code, t, bReg, -wordSize)
					defer MovFromStack.op(code, t, bReg, -wordSize)
				}

			case "mul":
				// scratch reg is the upper target reg, but we can use it as a factor reg
				bReg = regScratch
			}

			mach.OpMove(code, t, bReg, b)
		} else {
			defer code.Consumed(t, b)
		}
	} else {
		switch name {
		case "div_u":
			bStorage = values.TempReg
			bReg, ok = code.TryAllocReg(t)
			if ok {
				defer code.FreeReg(t, bReg)
				mach.OpMove(code, t, bReg, b)
				Test.op(code, t, bReg, bReg)
				Je.op(code, code.TrapLinks().DivideByZero.FinalAddress())
			} else {
				mach.OpMove(code, t, regScratch, b)
				Test.op(code, t, regScratch, regScratch)
				Je.op(code, code.TrapLinks().DivideByZero.FinalAddress())

				bReg = regTextPtr

				code.AddStackUsage(wordSize)
				Push.op(code, bReg)
				defer Pop.op(code, bReg)

				Mov.op(code, t, bReg, regScratch)
			}

		case "mul":
			switch bStorage {
			case values.Imm, values.Stack, values.ConditionFlags:
				bStorage = values.TempReg
				bReg = regTextPtr

				code.AddStackUsage(wordSize)
				Push.op(code, bReg)
				defer Pop.op(code, bReg)

				mach.OpMove(code, t, bReg, b)
			}
		}
	}

	aReg, own := mach.opBorrowResultReg(code, t, a)
	if aReg != regResult {
		// operand was in register, nothing was done
		mach.OpMove(code, t, regResult, a)
	}
	if own {
		code.FreeReg(t, aReg)
	}

	if name == "div_u" {
		Xor.opReg(code, t, regScratch, regScratch) // dividend high bits
	}

	switch bStorage {
	case values.VarMem:
		insn.opStack(code, t, b.Offset())

	case values.VarReg, values.TempReg:
		insn.opReg(code, t, bReg)

	default:
		panic(bStorage)
	}

	return values.TempRegOperand(regResult)
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
