package wag

import (
	"encoding/binary"
	"fmt"
)

var native = binary.LittleEndian

type branch struct {
	label int
	value int64
}

type Execution struct {
	mem []byte
}

type functionExecution struct {
	e      *Execution
	locals []int64
}

type functionParser struct {
	loader
	m      *Module
	labels int
}

func (p *functionParser) parse() func(*functionExecution) int64 {
	op := p.uint8()

	switch op {
	case opNop:
		return func(*functionExecution) (result int64) {
			println(opcodeNames[op])
			return
		}

	case opBlock:
		label := p.labels
		p.labels++

		exprs := make([]func(*functionExecution) int64, p.uint8())
		for i := range exprs {
			exprs[i] = p.parse()
		}

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			defer func() {
				if x := recover(); x != nil {
					if b, ok := x.(branch); ok && b.label == label {
						result = b.value
					} else {
						panic(x)
					}
				}
			}()

			for _, expr := range exprs {
				result = expr(fe)
			}
			return
		}

	case opLoop:
		labelBegin := p.labels
		p.labels++
		labelEnd := p.labels
		p.labels++

		exprs := make([]func(*functionExecution) int64, p.uint8())
		for i := range exprs {
			exprs[i] = p.parse()
		}

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			for {
				restart := false

				func() {
					defer func() {
						if x := recover(); x != nil {
							if b, ok := x.(branch); ok {
								switch b.label {
								case labelBegin:
									restart = true
									return

								case labelEnd:
									result = b.value
									return
								}
							}

							panic(x)
						}
					}()

					for _, expr := range exprs {
						result = expr(fe)
					}
				}()

				if !restart {
					return
				}
			}
		}

	case opIf:
		exprIf := p.parse()
		exprThen := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
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
			println(opcodeNames[op])
			if exprIf(fe) != 0 {
				return exprThen(fe)
			} else {
				return exprElse(fe)
			}
		}

	case opSelect:
		opNotImplemented(op)

	case opBr:
		label := int(p.uint8())
		expr := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			value := expr(fe)
			panic(branch{label, value})
		}

	case opBrIf:
		opNotImplemented(op)
	case opTableswitch:
		opNotImplemented(op)

	case opI8_Const:
		value := int64(p.int8())

		return func(*functionExecution) int64 {
			println(opcodeNames[op])
			return value
		}

	case opI32_Const:
		value := int64(p.uint32())

		return func(*functionExecution) int64 {
			println(opcodeNames[op])
			return value
		}

	case opI64_Const:
		opNotImplemented(op)
	case opF64_Const:
		opNotImplemented(op)
	case opF32_Const:
		opNotImplemented(op)

	case opGetLocal:
		index := p.uint8()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			return fe.locals[index]
		}

	case opSetLocal:
		index := p.uint8()
		expr := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			result = expr(fe)
			fe.locals[index] = result
			return
		}

	case opGetGlobal:
		opNotImplemented(op)
	case opSetGlobal:
		opNotImplemented(op)

	case opCall:
		funIndex := int(p.uint8())
		fun := &p.m.Functions[funIndex]
		numArgs := len(fun.Signature.ArgTypes)

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			return fun.execute(fe.e, make([]int64, numArgs))
		}

	case opCallIndirect:
		sigIndex := int(p.uint8())
		funExpr := p.parse()
		sig := &p.m.Signatures[sigIndex]
		numArgs := len(sig.ArgTypes)
		mainTable := p.m.Functions
		indirectTable := p.m.FunctionTable

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			indirectIndex := int32(funExpr(fe))
			mainIndex := indirectTable[indirectIndex]
			fun := mainTable[mainIndex]
			return fun.execute(fe.e, make([]int64, numArgs))
		}

	case opReturn:
		opNotImplemented(op)
	case opUnreachable:
		opNotImplemented(op)

	case opI32_LoadMem8S:
		operand := int64(p.uint8())
		expr := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			offset := expr(fe)
			address := offset + operand
			if address < offset {
				address = int64(cap(fe.e.mem))
			}
			return int64(int8(fe.e.mem[address]))
		}

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
		operand := int64(p.uint8())
		expr := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			offset := expr(fe)
			address := offset + operand
			if address < offset {
				address = int64(cap(fe.e.mem))
			}
			return int64(native.Uint32(fe.e.mem[address : address+4]))
		}

	case opI64_LoadMem:
		opNotImplemented(op)
	case opF32_LoadMem:
		opNotImplemented(op)
	case opF64_LoadMem:
		opNotImplemented(op)

	case opI32_StoreMem8:
		operand := int64(p.uint8())
		offsetExpr := p.parse()
		valueExpr := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			offset := offsetExpr(fe)
			address := offset + operand
			if address < offset {
				address = int64(cap(fe.e.mem))
			}
			result = valueExpr(fe)
			fe.e.mem[address] = uint8(result)
			return
		}

	case opI32_StoreMem16:
		opNotImplemented(op)
	case opI64_StoreMem8:
		opNotImplemented(op)
	case opI64_StoreMem16:
		opNotImplemented(op)
	case opI64_StoreMem32:
		opNotImplemented(op)

	case opI32_StoreMem:
		operand := int64(p.uint8())
		offsetExpr := p.parse()
		valueExpr := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			offset := offsetExpr(fe)
			address := offset + operand
			if address < offset {
				address = int64(cap(fe.e.mem))
			}
			result = valueExpr(fe)
			native.PutUint32(fe.e.mem[address:address+4], uint32(result))
			return
		}

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
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(uint32(valueL) + uint32(valueR))
		}

	case opI32_Sub:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(uint32(valueL) - uint32(valueR))
		}

	case opI32_Mul:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(uint32(valueL) * uint32(valueR))
		}

	case opI32_SDiv:
		opNotImplemented(op)
	case opI32_UDiv:
		opNotImplemented(op)
	case opI32_SRem:
		opNotImplemented(op)
	case opI32_URem:
		opNotImplemented(op)

	case opI32_AND:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(uint32(valueL) & uint32(valueR))
		}

	case opI32_OR:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(uint32(valueL) | uint32(valueR))
		}

	case opI32_XOR:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(uint32(valueL) ^ uint32(valueR))
		}

	case opI32_SHL:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(uint32(valueL) << uint(valueR))
		}

	case opI32_SHR:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(uint32(valueL) >> uint(valueR))
		}

	case opI32_SAR:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) int64 {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			return int64(int32(valueL) >> uint(valueR))
		}

	case opI32_EQ:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if uint32(valueL) == uint32(valueR) {
				result = 1
			}
			return
		}

	case opI32_NE:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if uint32(valueL) != uint32(valueR) {
				result = 1
			}
			return
		}

	case opI32_SLT:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if int32(valueL) < int32(valueR) {
				result = 1
			}
			return
		}

	case opI32_SLE:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if int32(valueL) <= int32(valueR) {
				result = 1
			}
			return
		}

	case opI32_ULT:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if uint32(valueL) < uint32(valueR) {
				result = 1
			}
			return
		}

	case opI32_ULE:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if uint32(valueL) <= uint32(valueR) {
				result = 1
			}
			return
		}

	case opI32_SGT:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if int32(valueL) > int32(valueR) {
				result = 1
			}
			return
		}

	case opI32_SGE:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if int32(valueL) >= int32(valueR) {
				result = 1
			}
			return
		}

	case opI32_UGT:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if uint32(valueL) > uint32(valueR) {
				result = 1
			}
			return
		}

	case opI32_UGE:
		exprL := p.parse()
		exprR := p.parse()

		return func(fe *functionExecution) (result int64) {
			println(opcodeNames[op])
			valueL := exprL(fe)
			valueR := exprR(fe)
			if uint32(valueL) >= uint32(valueR) {
				result = 1
			}
			return
		}

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

	panic(fmt.Errorf("unsupported opcode: 0x%02x", op))
}

func opNotImplemented(op uint8) {
	if name := opcodeNames[op]; name != "" {
		panic(fmt.Errorf("opcode not implemented: %s", name))
	} else {
		panic(fmt.Errorf("opcode not implemented: 0x%02x", op))
	}
}
