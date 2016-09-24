package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

type rexPrefix struct{}

func (rexPrefix) writeTo(code gen.Coder, t types.T, ro, index, rmOrBase byte) {
	writeRexSizeTo(code, t, ro, index, rmOrBase)
}

type rexWPrefix struct{}

func (rexWPrefix) writeTo(code gen.Coder, t types.T, ro, index, rmOrBase byte) {
	writeRexTo(code, rexW, ro, index, rmOrBase)
}

type data16RexPrefix struct{}

func (data16RexPrefix) writeTo(code gen.Coder, t types.T, ro, index, rmOrBase byte) {
	code.WriteByte(0x66)
	writeRexSizeTo(code, t, ro, index, rmOrBase)
}

var (
	Rex       rexPrefix
	RexW      rexWPrefix
	Data16Rex data16RexPrefix
)

var (
	Neg  = insnRexM{[]byte{0xf7}, 3}
	Mul  = insnRexM{[]byte{0xf7}, 4}
	Div  = insnRexM{[]byte{0xf7}, 6}
	Idiv = insnRexM{[]byte{0xf7}, 7}
	Inc  = insnRexM{[]byte{0xff}, 0}
	Dec  = insnRexM{[]byte{0xff}, 1}
	Shl  = insnRexM{[]byte{0xd3}, 4}
	Shr  = insnRexM{[]byte{0xd3}, 5}
	Sar  = insnRexM{[]byte{0xd3}, 7}

	Test    = insnPrefix{Rex, []byte{0x85}, nil}
	Cmovb   = insnPrefix{Rex, []byte{0x0f, 0x42}, nil}
	Cmovae  = insnPrefix{Rex, []byte{0x0f, 0x43}, nil}
	Cmove   = insnPrefix{Rex, []byte{0x0f, 0x44}, nil}
	Cmovne  = insnPrefix{Rex, []byte{0x0f, 0x45}, nil}
	Cmovbe  = insnPrefix{Rex, []byte{0x0f, 0x46}, nil}
	Cmova   = insnPrefix{Rex, []byte{0x0f, 0x47}, nil}
	Cmovl   = insnPrefix{Rex, []byte{0x0f, 0x4c}, nil}
	Cmovge  = insnPrefix{Rex, []byte{0x0f, 0x4d}, nil}
	Cmovle  = insnPrefix{Rex, []byte{0x0f, 0x4e}, nil}
	Cmovg   = insnPrefix{Rex, []byte{0x0f, 0x4f}, nil}
	Movzx8  = insnPrefix{Rex, []byte{0x0f, 0xb6}, nil}
	Movzx16 = insnPrefix{Rex, []byte{0x0f, 0xb7}, nil}
	Bsf     = insnPrefix{Rex, []byte{0x0f, 0xbc}, nil}
	Movsx8  = insnPrefix{Rex, []byte{0x0f, 0xbe}, nil}
	Movsx16 = insnPrefix{Rex, []byte{0x0f, 0xbf}, nil}
	Movsxd  = insnPrefix{RexW, []byte{0x63}, nil} // variable rexR, rexX and rexB

	MovImm   = insnPrefixMI{Rex, 0, 0, 0xc7, 0}
	CmpImm16 = insnPrefixMI{Data16Rex, 0, 0x81, 0, 7}

	Add = binaryInsn{
		insnPrefix{Rex, []byte{0x03}, nil},
		insnPrefixMI{Rex, 0x83, 0, 0x81, 0},
	}
	Or = binaryInsn{
		insnPrefix{Rex, []byte{0x0b}, nil},
		insnPrefixMI{Rex, 0x83, 0, 0x81, 1},
	}
	And = binaryInsn{
		insnPrefix{Rex, []byte{0x23}, nil},
		insnPrefixMI{Rex, 0x83, 0, 0x81, 4},
	}
	Sub = binaryInsn{
		insnPrefix{Rex, []byte{0x2b}, nil},
		insnPrefixMI{Rex, 0x83, 0, 0x81, 5},
	}
	Xor = binaryInsn{
		insnPrefix{Rex, []byte{0x33}, nil},
		insnPrefixMI{Rex, 0x83, 0, 0x81, 6},
	}
	Cmp = binaryInsn{
		insnPrefix{Rex, []byte{0x3b}, nil},
		insnPrefixMI{Rex, 0x83, 0, 0x81, 7},
	}
	Mov8 = binaryInsn{
		insnPrefix{Rex, []byte{0x8a}, []byte{0x88}},
		insnPrefixMI{Rex, 0xc6, 0, 0, 0},
	}
	Mov16 = binaryInsn{
		insnPrefix{Data16Rex, []byte{0x8b}, []byte{0x89}},
		insnPrefixMI{Data16Rex, 0, 0xc7, 0, 0},
	}
	Mov = binaryInsn{
		insnPrefix{Rex, []byte{0x8b}, []byte{0x89}},
		MovImm,
	}

	Push = pushPopInsn{
		insnO{0x50},
		insnRexM{[]byte{0xff}, 6},
	}
	Pop = pushPopInsn{
		insnO{0x58},
		insnRexM{[]byte{0x8f}, 0},
	}

	ShlImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 4},
		insnPrefixMI{Rex, 0xc1, 0, 0, 4},
	}
	ShrImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 5},
		insnPrefixMI{Rex, 0xc1, 0, 0, 5},
	}
	SarImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 7},
		insnPrefixMI{Rex, 0xc1, 0, 0, 7},
	}

	MovImm64 = movImmInsn{
		MovImm,
		insnRexOI{0xb8},
	}
)

var binaryIntInsns = map[string]binaryInsn{
	"add": Add,
	"and": And,
	"or":  Or,
	"sub": Sub,
	"xor": Xor,
}

var binaryIntDivMulInsns = map[string]struct {
	insnRexM
	shiftImm  shiftImmInsn
	division  bool // TODO: use enums for WebAssembly operators, and
	signed    bool //       incorporate these properties in the enum values?
	remainder bool //
}{
	"mul":   {Mul, ShlImm, false, false, false},
	"div_s": {Idiv, NoShiftImmInsn, true, true, false},
	"div_u": {Div, ShrImm, true, false, false},
	"rem_s": {Idiv, NoShiftImmInsn, true, true, true},
	"rem_u": {Div, NoShiftImmInsn, true, false, true}, // TODO: use AND for 2^n divisors
}

var binaryIntShiftInsns = map[string]struct {
	insnRexM
	imm shiftImmInsn
}{
	"shl":   {Shl, ShlImm},
	"shr_s": {Sar, SarImm},
	"shr_u": {Shr, ShrImm},
}

var binaryIntConditions = map[string]values.Condition{
	"eq":   values.EQ,
	"gt_s": values.GTSigned,
	"gt_u": values.GTUnsigned,
	"lt_s": values.LTSigned,
	"lt_u": values.LTUnsigned,
	"ne":   values.NE,
}

func (mach X86) unaryIntOp(code gen.RegCoder, name string, t types.T, x values.Operand) values.Operand {
	switch name {
	case "ctz":
		var targetReg regs.R

		sourceReg, zeroExt, own := mach.opBorrowMaybeScratchReg(code, t, x)
		if own {
			targetReg = sourceReg
		} else {
			targetReg, zeroExt = mach.opMaybeResultReg(code, t, values.NoOperand)
		}

		Bsf.opFromReg(code, t, targetReg, sourceReg)
		return values.TempRegOperand(targetReg, zeroExt)

	case "eqz":
		reg, _, own := mach.opBorrowMaybeScratchReg(code, t, x)
		if own {
			defer code.FreeReg(t, reg)
		}

		Test.opFromReg(code, t, reg, reg)
		return values.ConditionFlagsOperand(values.EQ)
	}

	panic(name)
}

func (mach X86) binaryIntOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) (result values.Operand, deadend bool) {
	switch a.Storage {
	case values.Stack, values.ConditionFlags:
		panic(a)
	}

	switch name {
	case "div_s", "div_u", "mul", "rem_s", "rem_u":
		return mach.binaryIntDivMulOp(code, name, t, a, b)

	case "shl", "shr_s", "shr_u":
		result = mach.binaryIntShiftOp(code, name, t, a, b)
		return

	default:
		result = mach.binaryIntGenericOp(code, name, t, a, b)
		return
	}
}

func (mach X86) binaryIntGenericOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	if value, ok := a.CheckImmValue(t); ok {
		switch {
		case value == 0 && name == "sub":
			reg, zeroExt := mach.opMaybeResultReg(code, t, b)
			Neg.opReg(code, t, reg)
			return values.TempRegOperand(reg, zeroExt)
		}
	}

	switch b.Storage {
	case values.Imm:
		value := b.ImmValue(t)

		switch {
		case (name == "add" && value == 1) || (name == "sub" && value == -1):
			reg, zeroExt := mach.opMaybeResultReg(code, t, a)
			Inc.opReg(code, t, reg)
			return values.TempRegOperand(reg, zeroExt)

		case (name == "sub" && value == 1) || (name == "add" && value == -1):
			reg, zeroExt := mach.opMaybeResultReg(code, t, a)
			Dec.opReg(code, t, reg)
			return values.TempRegOperand(reg, zeroExt)

		case value < -0x80000000 || value >= 0x80000000:
			reg, _, own := mach.opBorrowMaybeScratchReg(code, t, b)
			b = values.RegOperand(reg, own)
		}

	case values.Stack, values.ConditionFlags:
		reg, _, own := mach.opBorrowMaybeScratchReg(code, t, b)
		b = values.RegOperand(reg, own)
	}

	if insn, found := binaryIntInsns[name]; found {
		reg, zeroExt := mach.opMaybeResultReg(code, t, a)
		binaryInsnOp(code, insn, t, reg, b)
		return values.TempRegOperand(reg, zeroExt)
	} else if cond, found := binaryIntConditions[name]; found {
		reg, _, own := mach.opBorrowMaybeResultReg(code, t, a)
		if own {
			defer code.FreeReg(t, reg)
		}

		switch b.Storage {
		case values.Imm:
			Cmp.opImm(code, t, reg, int(b.ImmValue(t)))

		case values.ROData:
			Cmp.opFromAddr(code, t, reg, 0, NoIndex, code.RODataAddr()+b.Addr())

		case values.VarMem:
			Cmp.opFromStack(code, t, reg, b.Offset())

		case values.VarReg, values.TempReg, values.BorrowedReg:
			Cmp.opFromReg(code, t, reg, b.Reg())

		default:
			panic(b)
		}

		code.Consumed(t, b)

		return values.ConditionFlagsOperand(cond)
	}

	panic(name)
}

func (mach X86) binaryIntDivMulOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) (result values.Operand, deadend bool) {
	insn := binaryIntDivMulInsns[name]

	if value, ok := b.CheckImmValue(t); ok {
		switch {
		case value == -1:
			reg, zeroExt := mach.opMaybeResultReg(code, t, a)
			Neg.opReg(code, t, reg)
			result = values.TempRegOperand(reg, zeroExt)
			return

		case insn.shiftImm.defined() && value > 0 && isPowerOfTwo(uint64(value)):
			reg, zeroExt := mach.opMaybeResultReg(code, t, a)
			insn.shiftImm.op(code, t, reg, log2(uint64(value)))
			result = values.TempRegOperand(reg, zeroExt)
			return
		}
	}

	checkZero := true

	if reg, _, ok := b.CheckAnyReg(); ok {
		if reg == regResult {
			if insn.division {
				// can't use scratch reg as divisor since it contains the dividend high bits

				if reg, ok := code.TryAllocReg(t); ok {
					mach.OpMove(code, t, reg, b)
					b = values.RegOperand(reg, true)
				} else {
					mach.OpMove(code, t, regScratch, b)

					Push.op(code, regTextPtr)
					code.AddStackUsage(wordSize)
					defer Pop.op(code, regTextPtr)

					reg = regTextPtr

					Mov.opFromReg(code, t, reg, regScratch)
					b = values.RegOperand(reg, false)
				}
			} else {
				// scratch reg is the upper target reg, but we can use it as a multiplier

				mach.OpMove(code, t, regScratch, b)
				b = values.RegOperand(regScratch, false)
			}
		}
	} else {
		if insn.division {
			if value, ok := b.CheckImmValue(t); ok && value != 0 {
				checkZero = false
			}
		}

		if reg, ok := code.TryAllocReg(t); ok {
			mach.OpMove(code, t, reg, b)
			b = values.RegOperand(reg, true)
		} else {
			mach.OpMove(code, t, regScratch, b)

			Push.op(code, regTextPtr)
			code.AddStackUsage(wordSize)
			defer Pop.op(code, regTextPtr)

			reg = regTextPtr

			Mov.opFromReg(code, t, reg, regScratch)
			b = values.RegOperand(reg, false)
		}
	}

	mach.OpMove(code, t, regResult, a)

	if insn.division {
		if checkZero {
			mach.opCheckDivideByZero(code, t, b.Reg())
		}

		if insn.signed {
			// sign-extend dividend low bits to high bits
			Xor.opFromReg(code, t, regScratch, regScratch)
			Test.opFromReg(code, t, regResult, regResult)
			Setge.opReg(code, regScratch)
			Dec.opReg(code, t, regScratch)
		} else {
			// zero-extend dividend high bits
			Xor.opFromReg(code, t, regScratch, regScratch)
		}
	}

	insn.opReg(code, t, b.Reg())
	code.Consumed(t, b)

	if insn.remainder {
		Mov.opFromReg(code, t, regResult, regScratch)
	}

	result = values.TempRegOperand(regResult, false)
	return
}

func (mach X86) opCheckDivideByZero(code gen.RegCoder, t types.T, reg regs.R) {
	var end links.L

	Test.opFromReg(code, t, reg, reg)
	Jne.rel8.opStub(code)
	end.AddSite(code.Len())

	CallRel.op(code, code.TrapLinks().DivideByZero.Address)
	code.AddCallSite(&code.TrapLinks().DivideByZero)

	end.SetAddress(code.Len())
	mach.updateSites8(code, &end)
}

func (mach X86) binaryIntShiftOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	insn := binaryIntShiftInsns[name]

	targetReg, zeroExt := mach.opMaybeResultReg(code, t, a)

	switch b.Storage {
	case values.Imm:
		insn.imm.op(code, t, targetReg, int(b.ImmValue(t)))

	default:
		panic("TODO")
	}

	return values.TempRegOperand(targetReg, zeroExt)
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
