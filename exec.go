package wag

import (
	"fmt"
)

type Execution struct {
	mem []byte
}

type functionExecution struct {
	e    *Execution
	vars []int64
}

type functionParser struct {
	loader
}

func (p *functionParser) parse() func(*functionExecution) int64 {
	op := p.uint8()

	switch op {
	case opNop:
		return func(*functionExecution) (result int64) {
			return
		}

	case opBlock, opLoop:
		exprs := make([]func(*functionExecution) int64, p.uint8())

		for i := range exprs {
			exprs[i] = p.parse()
		}

		return func(fe *functionExecution) (result int64) {
			for _, expr := range exprs {
				result = expr(fe)
			}
			return
		}

	case opIf:
		exprIf := p.parse()
		exprThen := p.parse()

		return func(fe *functionExecution) (result int64) {
			if exprIf(fe) != 0 {
				exprThen(fe)
			}
			return
		}

	case opIfElse:
		exprIf := p.parse()
		exprThen := p.parse()
		exprElse := p.parse()

		return func(fe *functionExecution) int64 {
			if exprIf(fe) != 0 {
				return exprThen(fe)
			} else {
				return exprElse(fe)
			}
		}

	case opSelect:
		opNotImplemented(op)
	case opBr:
		opNotImplemented(op)
	case opBrIf:
		opNotImplemented(op)
	case opTableswitch:
		opNotImplemented(op)

	case opI8_Const:
		value := int64(p.uint8())

		return func(*functionExecution) int64 {
			return value
		}

	case opI32_Const:
		opNotImplemented(op)
	case opI64_Const:
		opNotImplemented(op)
	case opF64_Const:
		opNotImplemented(op)
	case opF32_Const:
		opNotImplemented(op)

	case opGetLocal:
		index := p.uint8()

		return func(fe *functionExecution) int64 {
			return fe.vars[index]
		}

	case opSetLocal:
		opNotImplemented(op)
	case opGetGlobal:
		opNotImplemented(op)
	case opSetGlobal:
		opNotImplemented(op)
	case opCall:
		opNotImplemented(op)
	case opCallIndirect:
		opNotImplemented(op)
	case opReturn:
		opNotImplemented(op)
	case opUnreachable:
		opNotImplemented(op)
	case opI32_LoadMem8S:
		opNotImplemented(op)
	case opI32_LoadMem8U:
		opNotImplemented(op)
	case opI32_LoadMem16S:
		opNotImplemented(op)
	case opI32_LoadMem16U:
		opNotImplemented(op)
	case opI64_LoadMem8S:
		opNotImplemented(op)
	case opI64_LoadMem8U:
		opNotImplemented(op)
	case opI64_LoadMem16S:
		opNotImplemented(op)
	case opI64_LoadMem16U:
		opNotImplemented(op)
	case opI64_LoadMem32S:
		opNotImplemented(op)
	case opI64_LoadMem32U:
		opNotImplemented(op)
	case opI32_LoadMem:
		opNotImplemented(op)
	case opI64_LoadMem:
		opNotImplemented(op)
	case opF32_LoadMem:
		opNotImplemented(op)
	case opF64_LoadMem:
		opNotImplemented(op)
	case opI32_StoreMem8:
		opNotImplemented(op)
	case opI32_StoreMem16:
		opNotImplemented(op)
	case opI64_StoreMem8:
		opNotImplemented(op)
	case opI64_StoreMem16:
		opNotImplemented(op)
	case opI64_StoreMem32:
		opNotImplemented(op)
	case opI32_StoreMem:
		opNotImplemented(op)
	case opI64_StoreMem:
		opNotImplemented(op)
	case opF32_StoreMem:
		opNotImplemented(op)
	case opF64_StoreMem:
		opNotImplemented(op)
	case opResizeMemory_I32:
		opNotImplemented(op)
	case opResizeMemory_I64:
		opNotImplemented(op)

	case opI32_Add:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			valueL := exprL(fe)
			valueR := exprR(fe)
			return valueL + valueR
		}

	case opI32_Sub:
		opNotImplemented(op)
	case opI32_Mul:
		opNotImplemented(op)
	case opI32_SDiv:
		opNotImplemented(op)
	case opI32_UDiv:
		opNotImplemented(op)
	case opI32_SRem:
		opNotImplemented(op)
	case opI32_URem:
		opNotImplemented(op)
	case opI32_AND:
		opNotImplemented(op)
	case opI32_OR:
		opNotImplemented(op)
	case opI32_XOR:
		opNotImplemented(op)
	case opI32_SHL:
		opNotImplemented(op)
	case opI32_SHR:
		opNotImplemented(op)
	case opI32_SAR:
		opNotImplemented(op)
	case opI32_EQ:
		opNotImplemented(op)
	case opI32_NE:
		opNotImplemented(op)
	case opI32_SLT:
		opNotImplemented(op)
	case opI32_SLE:
		opNotImplemented(op)
	case opI32_ULT:
		opNotImplemented(op)
	case opI32_ULE:
		opNotImplemented(op)
	case opI32_SGT:
		opNotImplemented(op)
	case opI32_SGE:
		opNotImplemented(op)
	case opI32_UGT:
		opNotImplemented(op)
	case opI32_UGE:
		opNotImplemented(op)
	case opI32_CLZ:
		opNotImplemented(op)
	case opI32_CTZ:
		opNotImplemented(op)
	case opI32_PopCnt:
		opNotImplemented(op)
	case opI32_NOT:
		opNotImplemented(op)
	case opI64_Add:
		opNotImplemented(op)
	case opI64_Sub:
		opNotImplemented(op)
	case opI64_Mul:
		opNotImplemented(op)
	case opI64_SDiv:
		opNotImplemented(op)
	case opI64_UDiv:
		opNotImplemented(op)
	case opI64_SRem:
		opNotImplemented(op)
	case opI64_URem:
		opNotImplemented(op)
	case opI64_AND:
		opNotImplemented(op)
	case opI64_OR:
		opNotImplemented(op)
	case opI64_XOR:
		opNotImplemented(op)
	case opI64_SHL:
		opNotImplemented(op)
	case opI64_SHR:
		opNotImplemented(op)
	case opI64_SAR:
		opNotImplemented(op)
	case opI64_EQ:
		opNotImplemented(op)
	case opI64_NE:
		opNotImplemented(op)
	case opI64_SLT:
		opNotImplemented(op)
	case opI64_SLE:
		opNotImplemented(op)
	case opI64_ULT:
		opNotImplemented(op)
	case opI64_ULE:
		opNotImplemented(op)
	case opI64_SGT:
		opNotImplemented(op)
	case opI64_SGE:
		opNotImplemented(op)
	case opI64_UGT:
		opNotImplemented(op)
	case opI64_UGE:
		opNotImplemented(op)
	case opI64_CLZ:
		opNotImplemented(op)
	case opI64_CTZ:
		opNotImplemented(op)
	case opI64_PopCnt:
		opNotImplemented(op)
	case opF32_Add:
		opNotImplemented(op)
	case opF32_Sub:
		opNotImplemented(op)
	case opF32_Mul:
		opNotImplemented(op)
	case opF32_Div:
		opNotImplemented(op)
	case opF32_Min:
		opNotImplemented(op)
	case opF32_Max:
		opNotImplemented(op)
	case opF32_Abs:
		opNotImplemented(op)
	case opF32_Neg:
		opNotImplemented(op)
	case opF32_CopySign:
		opNotImplemented(op)
	case opF32_Ceil:
		opNotImplemented(op)
	case opF32_Floor:
		opNotImplemented(op)
	case opF32_Trunc:
		opNotImplemented(op)
	case opF32_Nearest:
		opNotImplemented(op)
	case opF32_Sqrt:
		opNotImplemented(op)
	case opF32_EQ:
		opNotImplemented(op)
	case opF32_NE:
		opNotImplemented(op)
	case opF32_LT:
		opNotImplemented(op)
	case opF32_LE:
		opNotImplemented(op)
	case opF32_GT:
		opNotImplemented(op)
	case opF32_GE:
		opNotImplemented(op)
	case opF64_Add:
		opNotImplemented(op)
	case opF64_Sub:
		opNotImplemented(op)
	case opF64_Mul:
		opNotImplemented(op)
	case opF64_Div:
		opNotImplemented(op)
	case opF64_Min:
		opNotImplemented(op)
	case opF64_Max:
		opNotImplemented(op)
	case opF64_Abs:
		opNotImplemented(op)
	case opF64_Neg:
		opNotImplemented(op)
	case opF64_CopySign:
		opNotImplemented(op)
	case opF64_Ceil:
		opNotImplemented(op)
	case opF64_Floor:
		opNotImplemented(op)
	case opF64_Trunc:
		opNotImplemented(op)
	case opF64_Nearest:
		opNotImplemented(op)
	case opF64_Sqrt:
		opNotImplemented(op)
	case opF64_EQ:
		opNotImplemented(op)
	case opF64_NE:
		opNotImplemented(op)
	case opF64_LT:
		opNotImplemented(op)
	case opF64_LE:
		opNotImplemented(op)
	case opF64_GT:
		opNotImplemented(op)
	case opF64_GE:
		opNotImplemented(op)
	case opI32_SConvert_F32:
		opNotImplemented(op)
	case opI32_SConvert_F64:
		opNotImplemented(op)
	case opI32_UConvert_F32:
		opNotImplemented(op)
	case opI32_UConvert_F64:
		opNotImplemented(op)
	case opI32_Convert_I64:
		opNotImplemented(op)
	case opI64_SConvert_F32:
		opNotImplemented(op)
	case opI64_SConvert_F64:
		opNotImplemented(op)
	case opI64_UConvert_F32:
		opNotImplemented(op)
	case opI64_UConvert_F64:
		opNotImplemented(op)
	case opI64_SConvert_I32:
		opNotImplemented(op)
	case opI64_UConvert_I32:
		opNotImplemented(op)
	case opF32_SConvert_I32:
		opNotImplemented(op)
	case opF32_UConvert_I32:
		opNotImplemented(op)
	case opF32_SConvert_I64:
		opNotImplemented(op)
	case opF32_UConvert_I64:
		opNotImplemented(op)
	case opF32_Convert_F64:
		opNotImplemented(op)
	case opF32_Reinterpret_I32:
		opNotImplemented(op)
	case opF64_SConvert_I32:
		opNotImplemented(op)
	case opF64_UConvert_I32:
		opNotImplemented(op)
	case opF64_SConvert_I64:
		opNotImplemented(op)
	case opF64_UConvert_I64:
		opNotImplemented(op)
	case opF64_Convert_F32:
		opNotImplemented(op)
	case opF64_Reinterpret_I64:
		opNotImplemented(op)
	case opI32_Reinterpret_F32:
		opNotImplemented(op)
	case opI64_Reinterpret_F64:
		opNotImplemented(op)
	}

	panic(fmt.Errorf("unsupported opcode: %d", op))
}

func opNotImplemented(op uint8) {
	panic(fmt.Errorf("opcode not implemented: 0x%02x", op))
}
