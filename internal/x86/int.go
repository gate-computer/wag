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

type data16RexPrefix struct{}

func (data16RexPrefix) writeTo(code gen.Coder, t types.T, ro, index, rmOrBase byte) {
	code.WriteByte(0x66)
	writeRexSizeTo(code, t, ro, index, rmOrBase)
}

var (
	Rex       rexPrefix
	Data16Rex data16RexPrefix
)

var (
	Neg = insnRexM{[]byte{0xf7}, 3}
	Mul = insnRexM{[]byte{0xf7}, 4}
	Div = insnRexM{[]byte{0xf7}, 6}
	Inc = insnRexM{[]byte{0xff}, 0}
	Dec = insnRexM{[]byte{0xff}, 1}

	Movsxd  = insnPrefix{Rex, []byte{0x63}, nil}
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
		insnPrefixMI{Rex, 0xc1, 0, 0, 0},
	}
	ShrImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 5},
		insnPrefixMI{Rex, 0xc1, 0, 0, 5},
	}

	MovImm64 = movImmInsn{
		MovImm,
		insnRexOI{0xb8},
	}
)

var (
	NoImmInst = insnPrefixMI{nil, 0, 0, 0, 0}
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
	shiftImm shiftImmInsn
}{
	"div_u": {Div, ShrImm},
	"mul":   {Mul, ShlImm},
}

var binaryIntConditions = map[string]values.Condition{
	"eq":   values.EQ,
	"gt_s": values.GTSigned,
	"gt_u": values.GTUnsigned,
	"lt_s": values.LTSigned,
	"ne":   values.NE,
}

func (mach X86) unaryIntOp(code gen.RegCoder, name string, t types.T, x values.Operand) values.Operand {
	switch name {
	case "ctz":
		var targetReg regs.R

		sourceReg, zeroExt, own := mach.opBorrowScratchReg(code, t, x)
		if own {
			targetReg = sourceReg
		} else {
			targetReg, zeroExt = mach.opResultReg(code, t, values.NoOperand)
		}

		Bsf.opFromReg(code, t, targetReg, sourceReg)
		return values.TempRegOperand(targetReg, zeroExt)

	case "eqz":
		reg, _, own := mach.opBorrowScratchReg(code, t, x)
		if own {
			defer code.FreeReg(t, reg)
		}

		Test.opFromReg(code, t, reg, reg)
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
			reg, zeroExt := mach.opResultReg(code, t, b)
			Neg.opReg(code, t, reg)
			return values.TempRegOperand(reg, zeroExt)
		}
	}

	switch b.Storage {
	case values.Imm:
		value := b.ImmValue(t)

		switch {
		case (name == "add" && value == 1) || (name == "sub" && value == -1):
			reg, zeroExt := mach.opResultReg(code, t, a)
			Inc.opReg(code, t, reg)
			return values.TempRegOperand(reg, zeroExt)

		case (name == "sub" && value == 1) || (name == "add" && value == -1):
			reg, zeroExt := mach.opResultReg(code, t, a)
			Dec.opReg(code, t, reg)
			return values.TempRegOperand(reg, zeroExt)

		case value < -0x80000000 || value >= 0x80000000:
			reg, _, own := mach.opBorrowScratchReg(code, t, b)
			b = values.RegOperand(reg, own)
		}

	case values.Stack, values.ConditionFlags:
		reg, _, own := mach.opBorrowScratchReg(code, t, b)
		b = values.RegOperand(reg, own)
	}

	if insn, found := binaryIntInsns[name]; found {
		reg, zeroExt := mach.opResultReg(code, t, a)
		binaryInsnOp(code, insn, t, reg, b)
		return values.TempRegOperand(reg, zeroExt)
	} else if cond, found := binaryIntConditions[name]; found {
		reg, _, own := mach.opBorrowResultReg(code, t, a)
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

func (mach X86) binaryIntDivMulOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	insn := binaryIntDivMulInsns[name]

	if value, ok := b.CheckImmValue(t); ok {
		switch {
		case value == -1:
			reg, zeroExt := mach.opResultReg(code, t, a)
			Neg.opReg(code, t, reg)
			return values.TempRegOperand(reg, zeroExt)

		case value > 0 && isPowerOfTwo(uint64(value)):
			reg, zeroExt := mach.opResultReg(code, t, a)
			insn.shiftImm.op(code, t, reg, log2(uint64(value)))
			return values.TempRegOperand(reg, zeroExt)
		}
	}

	bStorage := b.Storage
	bReg, _, ok := b.CheckAnyReg()
	if ok {
		if name == "div_u" {
			mach.opCheckDivideByZero(code, t, bReg)
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
					Mov.opToStack(code, t, bReg, -wordSize)
					defer Mov.opFromStack(code, t, bReg, -wordSize)
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
				mach.opCheckDivideByZero(code, t, bReg)
			} else {
				mach.OpMove(code, t, regScratch, b)
				mach.opCheckDivideByZero(code, t, regScratch)

				bReg = regTextPtr

				code.AddStackUsage(wordSize)
				Push.op(code, bReg)
				defer Pop.op(code, bReg)

				Mov.opFromReg(code, t, bReg, regScratch)
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

	aReg, _, own := mach.opBorrowResultReg(code, t, a)
	if aReg != regResult {
		// operand was in register, nothing was done
		mach.OpMove(code, t, regResult, a)
	}
	if own {
		code.FreeReg(t, aReg)
	}

	if name == "div_u" {
		Xor.opFromReg(code, t, regScratch, regScratch) // dividend high bits
	}

	switch bStorage {
	case values.VarMem:
		insn.opStack(code, t, b.Offset())

	case values.VarReg, values.TempReg:
		insn.opReg(code, t, bReg)

	default:
		panic(bStorage)
	}

	return values.TempRegOperand(regResult, false) // TODO: extension?
}

func (mach X86) opCheckDivideByZero(code gen.RegCoder, t types.T, reg regs.R) {
	var after links.L

	Test.opFromReg(code, t, reg, reg)
	Jne.rel8.opStub(code)
	after.AddSite(code.Len())

	CallRel.op(code, code.TrapLinks().DivideByZero.Address)
	code.AddCallSite(&code.TrapLinks().DivideByZero)

	after.SetAddress(code.Len())
	mach.updateSites8(code, &after)
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
