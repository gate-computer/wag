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
	Rol  = insnRexM{[]byte{0xd3}, 0}
	Ror  = insnRexM{[]byte{0xd3}, 1}
	Shl  = insnRexM{[]byte{0xd3}, 4}
	Shr  = insnRexM{[]byte{0xd3}, 5}
	Sar  = insnRexM{[]byte{0xd3}, 7}

	Test    = insnPrefix{Rex, []byte{0x85}, nil}
	Xchg    = insnPrefix{Rex, []byte{0x87}, []byte{0x87}}
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
	Bsr     = insnPrefix{Rex, []byte{0x0f, 0xbd}, nil}
	Movsx8  = insnPrefix{Rex, []byte{0x0f, 0xbe}, nil}
	Movsx16 = insnPrefix{Rex, []byte{0x0f, 0xbf}, nil}
	Movsxd  = insnPrefix{RexW, []byte{0x63}, nil} // variable rexR, rexX and rexB
	Popcnt  = insnPrefix{Prefixes{Prefix{0xf3}, Rex}, []byte{0x0f, 0xb8}, nil}

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

	RolImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 0},
		insnPrefixMI{Rex, 0xc1, 0, 0, 0},
	}
	RorImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 1},
		insnPrefixMI{Rex, 0xc1, 0, 0, 1},
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

var unaryIntInsns = map[string]insnPrefix{
	"clz":    Bsr,
	"ctz":    Bsf,
	"popcnt": Popcnt,
}

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
	"rotl":  {Rol, RolImm},
	"rotr":  {Ror, RorImm},
	"shl":   {Shl, ShlImm},
	"shr_s": {Sar, SarImm},
	"shr_u": {Shr, ShrImm},
}

var binaryIntConditions = map[string]values.Condition{
	"eq":   values.EQ,
	"ge_s": values.GESigned,
	"ge_u": values.GEUnsigned,
	"gt_s": values.GTSigned,
	"gt_u": values.GTUnsigned,
	"le_s": values.LESigned,
	"le_u": values.LEUnsigned,
	"lt_s": values.LTSigned,
	"lt_u": values.LTUnsigned,
	"ne":   values.NE,
}

func (mach X86) unaryIntOp(code gen.RegCoder, name string, t types.T, x values.Operand) values.Operand {
	switch name {
	case "eqz":
		reg, _, own := mach.opBorrowMaybeScratchReg(code, t, x, false)
		if own {
			defer code.FreeReg(t, reg)
		}

		Test.opFromReg(code, t, reg, reg)
		return values.ConditionFlagsOperand(values.EQ)
	}

	if insn, found := unaryIntInsns[name]; found {
		var targetReg regs.R

		sourceReg, _, own := mach.opBorrowMaybeScratchReg(code, t, x, false)
		if own {
			targetReg = sourceReg
		} else {
			targetReg, _ = mach.opMaybeResultReg(code, t, values.NoOperand, false)
		}

		switch name {
		case "clz":
			insn.opFromReg(code, t, regScratch, sourceReg)
			MovImm.opImm(code, t, targetReg, -1)
			Cmove.opFromReg(code, t, regScratch, targetReg)
			MovImm.opImm(code, t, targetReg, int(t.Size())*8-1)
			Sub.opFromReg(code, t, targetReg, regScratch)

		case "ctz":
			insn.opFromReg(code, t, targetReg, sourceReg)
			MovImm.opImm(code, t, regScratch, int(t.Size())*8)
			Cmove.opFromReg(code, t, targetReg, regScratch)

		case "popcnt":
			insn.opFromReg(code, t, targetReg, sourceReg)

		default:
			panic(name)
		}

		return values.TempRegOperand(targetReg, true)
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

	case "rotl", "rotr", "shl", "shr_s", "shr_u":
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
			reg, _ := mach.opMaybeResultReg(code, t, b, false)
			Neg.opReg(code, t, reg)
			return values.TempRegOperand(reg, true)
		}
	}

	switch b.Storage {
	case values.Imm:
		value := b.ImmValue(t)

		switch {
		case (name == "add" && value == 1) || (name == "sub" && value == -1):
			reg, _ := mach.opMaybeResultReg(code, t, a, false)
			Inc.opReg(code, t, reg)
			return values.TempRegOperand(reg, true)

		case (name == "sub" && value == 1) || (name == "add" && value == -1):
			reg, _ := mach.opMaybeResultReg(code, t, a, false)
			Dec.opReg(code, t, reg)
			return values.TempRegOperand(reg, true)

		case value < -0x80000000 || value >= 0x80000000:
			reg, _, own := mach.opBorrowMaybeScratchReg(code, t, b, true)
			b = values.RegOperand(reg, own)
		}

	case values.Stack, values.ConditionFlags:
		reg, _, own := mach.opBorrowMaybeScratchReg(code, t, b, true)
		b = values.RegOperand(reg, own)
	}

	if insn, found := binaryIntInsns[name]; found {
		reg, _ := mach.opMaybeResultReg(code, t, a, false)
		binaryInsnOp(code, insn, t, reg, b)
		return values.TempRegOperand(reg, true)
	} else if cond, found := binaryIntConditions[name]; found {
		reg, _, own := mach.opBorrowMaybeResultReg(code, t, a, false)
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
			reg, _ := mach.opMaybeResultReg(code, t, a, false)
			Neg.opReg(code, t, reg)
			result = values.TempRegOperand(reg, true)
			return

		case insn.shiftImm.defined() && value > 0 && isPowerOfTwo(uint64(value)):
			reg, _ := mach.opMaybeResultReg(code, t, a, false)
			insn.shiftImm.op(code, t, reg, log2(uint64(value)))
			result = values.TempRegOperand(reg, true)
			return
		}
	}

	checkZero := true
	checkOverflow := true

	if value, ok := a.CheckImmValue(t); ok {
		switch t.Size() {
		case types.Size32:
			if value != -0x80000000 {
				checkOverflow = false
			}

		case types.Size64:
			if value != -0x8000000000000000 {
				checkOverflow = false
			}
		}
	}

	if reg, _, ok := b.CheckAnyReg(); ok {
		if reg == regResult {
			if insn.division {
				// can't use scratch reg as divisor since it contains the dividend high bits

				if reg, ok := code.TryAllocReg(t); ok {
					mach.OpMove(code, t, reg, b, true)
					b = values.RegOperand(reg, true)
				} else {
					mach.OpMove(code, t, regScratch, b, true)

					Push.op(code, regTextPtr)
					code.AddStackUsage(wordSize)
					defer Pop.op(code, regTextPtr)

					reg = regTextPtr

					Mov.opFromReg(code, t, reg, regScratch)
					b = values.RegOperand(reg, false)
				}
			} else {
				// scratch reg is the upper target reg, but we can use it as a multiplier

				mach.OpMove(code, t, regScratch, b, true)
				b = values.RegOperand(regScratch, false)
			}
		}
	} else {
		if insn.division {
			if value, ok := b.CheckImmValue(t); ok {
				switch {
				case value != 0:
					checkZero = false

				case value != -1:
					checkOverflow = false
				}
			}
		}

		if reg, ok := code.TryAllocReg(t); ok {
			mach.OpMove(code, t, reg, b, true)
			b = values.RegOperand(reg, true)
		} else {
			mach.OpMove(code, t, regScratch, b, true)

			Push.op(code, regTextPtr)
			code.AddStackUsage(wordSize)
			defer Pop.op(code, regTextPtr)

			reg = regTextPtr

			Mov.opFromReg(code, t, reg, regScratch)
			b = values.RegOperand(reg, false)
		}
	}

	mach.OpMove(code, t, regResult, a, false)

	var doNot links.L

	if insn.division {
		if checkZero {
			mach.opCheckDivideByZero(code, t, b.Reg())
		}

		if insn.signed && checkOverflow {
			var do links.L

			if insn.remainder {
				Xor.opFromReg(code, t, regScratch, regScratch) // moved to result at the end

				Cmp.opImm(code, t, b.Reg(), -1)
				Je.rel8.opStub(code)
				doNot.AddSite(code.Len())
			} else {
				switch t.Size() {
				case types.Size32:
					Cmp.opImm(code, t, regResult, -0x80000000)

				case types.Size64:
					MovImm64.op(code, t, regScratch, -0x8000000000000000)
					Cmp.opFromReg(code, t, regResult, regScratch)

				default:
					panic(t)
				}

				Jne.rel8.opStub(code)
				do.AddSite(code.Len())

				Cmp.opImm(code, t, b.Reg(), -1)
				Jne.rel8.opStub(code)
				do.AddSite(code.Len())

				CallRel.op(code, code.TrapLinks().IntegerOverflow.Address)
				code.AddCallSite(&code.TrapLinks().IntegerOverflow)
			}

			do.SetAddress(code.Len())
			mach.updateSites8(code, &do)
		}

		if insn.signed {
			// sign-extend dividend low bits to high bits
			CdqCqo.op(code, t)
		} else {
			// zero-extend dividend high bits
			Xor.opFromReg(code, t, regScratch, regScratch)
		}
	}

	insn.opReg(code, t, b.Reg())
	code.Consumed(t, b)

	doNot.SetAddress(code.Len())
	mach.updateSites8(code, &doNot)

	if insn.remainder {
		Mov.opFromReg(code, t, regResult, regScratch)
	}

	result = values.TempRegOperand(regResult, true)
	return
}

func (mach X86) opCheckDivideByZero(code gen.RegCoder, t types.T, reg regs.R) {
	var end links.L

	Test.opFromReg(code, t, reg, reg)
	Jne.rel8.opStub(code)
	end.AddSite(code.Len())

	CallRel.op(code, code.TrapLinks().IntegerDivideByZero.Address)
	code.AddCallSite(&code.TrapLinks().IntegerDivideByZero)

	end.SetAddress(code.Len())
	mach.updateSites8(code, &end)
}

func (mach X86) binaryIntShiftOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	insn := binaryIntShiftInsns[name]

	targetReg, _ := mach.opMaybeResultReg(code, t, a, true)
	if targetReg == regShiftCount {
		Mov.opFromReg(code, t, regResult, targetReg)
		code.FreeReg(t, targetReg)
		targetReg = regResult
	}

	switch b.Storage {
	case values.Imm:
		insn.imm.op(code, t, targetReg, int(b.ImmValue(t)))

	default:
		if reg, _, ok := b.CheckAnyReg(); !ok || reg != regShiftCount {
			if code.RegAllocated(types.I32, regShiftCount) {
				Mov.opFromReg(code, types.I64, regScratch, regShiftCount)
				defer Mov.opFromReg(code, types.I64, regShiftCount, regScratch)
			}

			mach.OpMove(code, types.I32, regShiftCount, b, false) // TODO: 8-bit mov
		}

		insn.opReg(code, t, targetReg)
	}

	return values.TempRegOperand(targetReg, true)
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
