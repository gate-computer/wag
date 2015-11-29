package wag

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func asError(x interface{}) error {
	switch y := x.(type) {
	case error:
		return y

	default:
		return fmt.Errorf("%v", x)
	}
}

const (
	sectionMemory = iota
	sectionSignatures
	sectionFunctions
	sectionGlobals
	sectionDataSegments
	sectionFunctionTable
	sectionEnd
)

type Type int

const (
	TypeVoid = Type(0)
	TypeI32  = Type(1)
	TypeI64  = Type(2)
	TypeF32  = Type(4)
	TypeF64  = Type(8)
)

func (t Type) String() string {
	switch t {
	case TypeVoid:
		return "void"
	case TypeI32:
		return "i32"
	case TypeI64:
		return "i64"
	case TypeF32:
		return "f32"
	case TypeF64:
		return "f64"
	default:
		return strconv.Itoa(int(t))
	}
}

type FunctionFlags int

const (
	FunctionFlagName   = FunctionFlags(1)
	FunctionFlagImport = FunctionFlags(2)
	FunctionFlagLocals = FunctionFlags(4)
	FunctionFlagExport = FunctionFlags(8)
)

func (flags FunctionFlags) String() (s string) {
	var tokens []string

	if flags&FunctionFlagName != 0 {
		tokens = append(tokens, "name")
	}
	if flags&FunctionFlagImport != 0 {
		tokens = append(tokens, "import")
	}
	if flags&FunctionFlagLocals != 0 {
		tokens = append(tokens, "locals")
	}
	if flags&FunctionFlagExport != 0 {
		tokens = append(tokens, "export")
	}

	return strings.Join(tokens, "|")
}

type Module struct {
	Memory     Memory
	Signatures []Signature
	Functions  []Function
}

func LoadModule(data []byte) (m *Module, err error) {
	defer func() {
		if x := recover(); x != nil {
			err = asError(x)
		}
	}()

	m = loadModule(data)
	return
}

func loadModule(data []byte) (m *Module) {
	l := &loader{data}
	m = &Module{}

	for end := false; len(data) > 0 && !end; {
		section := int(l.uint8())

		switch section {
		case sectionMemory:
			m.Memory.MinSize = l.uint8log2int()
			m.Memory.MaxSize = l.uint8log2int()
			m.Memory.DefaultExport = (l.uint8() != 0)

		case sectionSignatures:
			num := l.leb128size()
			for i := 0; i < num; i++ {
				m.Signatures = append(m.Signatures, loadSignature(l, m))
			}

		case sectionFunctions:
			num := l.leb128size()
			for i := 0; i < num; i++ {
				m.Functions = append(m.Functions, loadFunction(l, m))
			}

		case sectionEnd:
			end = true

		default:
			panic(fmt.Errorf("unsupported section: %d", section))
		}
	}

	// XXX: end data

	return
}

type Memory struct {
	MinSize       int
	MaxSize       int
	DefaultExport bool
}

type Signature struct {
	ArgTypes   []Type
	ResultType Type
}

func loadSignature(l *loader, m *Module) (s Signature) {
	numArgs := int(l.uint8())
	resultType := Type(l.uint8())

	s = Signature{
		ResultType: resultType,
	}

	for j := 0; j < numArgs; j++ {
		s.ArgTypes = append(s.ArgTypes, Type(l.uint8()))
	}

	return
}

func (sig *Signature) String() (s string) {
	s = "("
	for i, t := range sig.ArgTypes {
		if i > 0 {
			s += ","
		}
		s += t.String()
	}
	s += ")->" + sig.ResultType.String()
	return
}

type Function struct {
	Flags     FunctionFlags
	Signature *Signature

	expr func(*functionExecution) int64
}

func loadFunction(l *loader, m *Module) (f Function) {
	flags := FunctionFlags(l.uint8())
	sigIndex := int(l.uint16())
	l.uint32() // name offset
	bodySize := int(l.uint16())

	if sigIndex >= len(m.Signatures) {
		panic("function signature index out of bounds")
	}

	f = Function{
		Flags:     flags,
		Signature: &m.Signatures[sigIndex],
	}

	if bodySize > 0 {
		p := parser{loader{l.data(bodySize)}}
		f.expr = p.parse()
	}

	return
}

func (f *Function) Execute(args []int64) (result int64, err error) {
	defer func() {
		if x := recover(); x != nil {
			err = asError(x)
		}
	}()

	result = f.execute(args)
	return
}

func (f *Function) execute(args []int64) int64 {
	fe := functionExecution{
		vars: args,
	}

	return f.expr(&fe)
}

func (f *Function) String() string {
	return fmt.Sprintf("%s %s", f.Flags, f.Signature)
}

type loader struct {
	buf []byte
}

func (l *loader) data(size int) (data []byte) {
	if len(l.buf) < size {
		panic(io.EOF)
	}
	data = l.buf[:size]
	l.buf = l.buf[size:]
	return
}

func (l *loader) uint8() (value uint8) {
	if len(l.buf) < 1 {
		panic(io.EOF)
	}
	value = l.buf[0]
	l.buf = l.buf[1:]
	return
}

func (l *loader) uint16() (value uint16) {
	if len(l.buf) < 2 {
		panic(io.EOF)
	}
	value = binary.LittleEndian.Uint16(l.buf[:2])
	l.buf = l.buf[2:]
	return
}

func (l *loader) uint32() (value uint32) {
	if len(l.buf) < 4 {
		panic(io.EOF)
	}
	value = binary.LittleEndian.Uint32(l.buf[:4])
	l.buf = l.buf[4:]
	return
}

func (l *loader) uint8log2int() int {
	return 1 << l.uint8()
}

func (l *loader) leb128() (c uint32, bits uint) {
	for i := 0; i < len(l.buf); i++ {
		byte := l.buf[i]
		c |= uint32(byte&0x7f) << bits
		bits += 7
		if byte&0x80 == 0 {
			l.buf = l.buf[i+1:]
			return c, bits
		}
		if i == 4 {
			panic("encoded integer is too long")
		}
	}
	panic(io.EOF)
}

func (l *loader) leb128uint32() (value uint32) {
	value, _ = l.leb128()
	return
}

func (l *loader) leb128int32() (value int32) {
	x, bits := l.leb128()
	value = int32(x)
	if value&(1<<(bits-1)) != 0 {
		value |= -1 << bits
	}
	return
}

func (l *loader) leb128size() (value int) {
	x, _ := l.leb128()
	value = int(x)
	if value < 0 {
		panic("unsigned integer value is too large for the implementation")
	}
	return
}

const (
	opNop                 = 0x00
	opBlock               = 0x01
	opLoop                = 0x02
	opIf                  = 0x03
	opIfElse              = 0x04
	opSelect              = 0x05
	opBr                  = 0x06
	opBrIf                = 0x07
	opTableswitch         = 0x08
	opI8_Const            = 0x09
	opI32_Const           = 0x0a
	opI64_Const           = 0x0b
	opF64_Const           = 0x0c
	opF32_Const           = 0x0d
	opGetLocal            = 0x0e
	opSetLocal            = 0x0f
	opGetGlobal           = 0x10
	opSetGlobal           = 0x11
	opCall                = 0x12
	opCallIndirect        = 0x13
	opReturn              = 0x14
	opUnreachable         = 0x15
	opI32_LoadMem8S       = 0x20
	opI32_LoadMem8U       = 0x21
	opI32_LoadMem16S      = 0x22
	opI32_LoadMem16U      = 0x23
	opI64_LoadMem8S       = 0x24
	opI64_LoadMem8U       = 0x25
	opI64_LoadMem16S      = 0x26
	opI64_LoadMem16U      = 0x27
	opI64_LoadMem32S      = 0x28
	opI64_LoadMem32U      = 0x29
	opI32_LoadMem         = 0x2a
	opI64_LoadMem         = 0x2b
	opF32_LoadMem         = 0x2c
	opF64_LoadMem         = 0x2d
	opI32_StoreMem8       = 0x2e
	opI32_StoreMem16      = 0x2f
	opI64_StoreMem8       = 0x30
	opI64_StoreMem16      = 0x31
	opI64_StoreMem32      = 0x32
	opI32_StoreMem        = 0x33
	opI64_StoreMem        = 0x34
	opF32_StoreMem        = 0x35
	opF64_StoreMem        = 0x36
	opResizeMemory_I32    = 0x39
	opResizeMemory_I64    = 0x3a
	opI32_Add             = 0x40
	opI32_Sub             = 0x41
	opI32_Mul             = 0x42
	opI32_SDiv            = 0x43
	opI32_UDiv            = 0x44
	opI32_SRem            = 0x45
	opI32_URem            = 0x46
	opI32_AND             = 0x47
	opI32_OR              = 0x48
	opI32_XOR             = 0x49
	opI32_SHL             = 0x4a
	opI32_SHR             = 0x4b
	opI32_SAR             = 0x4c
	opI32_EQ              = 0x4d
	opI32_NE              = 0x4e
	opI32_SLT             = 0x4f
	opI32_SLE             = 0x50
	opI32_ULT             = 0x51
	opI32_ULE             = 0x52
	opI32_SGT             = 0x53
	opI32_SGE             = 0x54
	opI32_UGT             = 0x55
	opI32_UGE             = 0x56
	opI32_CLZ             = 0x57
	opI32_CTZ             = 0x58
	opI32_PopCnt          = 0x59
	opI32_NOT             = 0x5a
	opI64_Add             = 0x5b
	opI64_Sub             = 0x5c
	opI64_Mul             = 0x5d
	opI64_SDiv            = 0x5e
	opI64_UDiv            = 0x5f
	opI64_SRem            = 0x60
	opI64_URem            = 0x61
	opI64_AND             = 0x62
	opI64_OR              = 0x63
	opI64_XOR             = 0x64
	opI64_SHL             = 0x65
	opI64_SHR             = 0x66
	opI64_SAR             = 0x67
	opI64_EQ              = 0x68
	opI64_NE              = 0x69
	opI64_SLT             = 0x6a
	opI64_SLE             = 0x6b
	opI64_ULT             = 0x6c
	opI64_ULE             = 0x6d
	opI64_SGT             = 0x6e
	opI64_SGE             = 0x6f
	opI64_UGT             = 0x70
	opI64_UGE             = 0x71
	opI64_CLZ             = 0x72
	opI64_CTZ             = 0x73
	opI64_PopCnt          = 0x74
	opF32_Add             = 0x75
	opF32_Sub             = 0x76
	opF32_Mul             = 0x77
	opF32_Div             = 0x78
	opF32_Min             = 0x79
	opF32_Max             = 0x7a
	opF32_Abs             = 0x7b
	opF32_Neg             = 0x7c
	opF32_CopySign        = 0x7d
	opF32_Ceil            = 0x7e
	opF32_Floor           = 0x7f
	opF32_Trunc           = 0x80
	opF32_Nearest         = 0x81
	opF32_Sqrt            = 0x82
	opF32_EQ              = 0x83
	opF32_NE              = 0x84
	opF32_LT              = 0x85
	opF32_LE              = 0x86
	opF32_GT              = 0x87
	opF32_GE              = 0x88
	opF64_Add             = 0x89
	opF64_Sub             = 0x8a
	opF64_Mul             = 0x8b
	opF64_Div             = 0x8c
	opF64_Min             = 0x8d
	opF64_Max             = 0x8e
	opF64_Abs             = 0x8f
	opF64_Neg             = 0x90
	opF64_CopySign        = 0x91
	opF64_Ceil            = 0x92
	opF64_Floor           = 0x93
	opF64_Trunc           = 0x94
	opF64_Nearest         = 0x95
	opF64_Sqrt            = 0x96
	opF64_EQ              = 0x97
	opF64_NE              = 0x98
	opF64_LT              = 0x99
	opF64_LE              = 0x9a
	opF64_GT              = 0x9b
	opF64_GE              = 0x9c
	opI32_SConvert_F32    = 0x9d
	opI32_SConvert_F64    = 0x9e
	opI32_UConvert_F32    = 0x9f
	opI32_UConvert_F64    = 0xa0
	opI32_Convert_I64     = 0xa1
	opI64_SConvert_F32    = 0xa2
	opI64_SConvert_F64    = 0xa3
	opI64_UConvert_F32    = 0xa4
	opI64_UConvert_F64    = 0xa5
	opI64_SConvert_I32    = 0xa6
	opI64_UConvert_I32    = 0xa7
	opF32_SConvert_I32    = 0xa8
	opF32_UConvert_I32    = 0xa9
	opF32_SConvert_I64    = 0xaa
	opF32_UConvert_I64    = 0xab
	opF32_Convert_F64     = 0xac
	opF32_Reinterpret_I32 = 0xad
	opF64_SConvert_I32    = 0xae
	opF64_UConvert_I32    = 0xaf
	opF64_SConvert_I64    = 0xb0
	opF64_UConvert_I64    = 0xb1
	opF64_Convert_F32     = 0xb2
	opF64_Reinterpret_I64 = 0xb3
	opI32_Reinterpret_F32 = 0xb4
	opI64_Reinterpret_F64 = 0xb5
)

type parser struct {
	loader
}

func (p *parser) parse() func(*functionExecution) int64 {
	op := p.uint8()

	switch op {
	case opNop:
		return func(*functionExecution) int64 {
			return 0
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
		expr0 := p.parse()
		expr1 := p.parse()

		return func(fe *functionExecution) int64 {
			if expr0(fe) != 0 {
				expr1(fe)
			}
			return 0
		}

	case opIfElse:
		expr0 := p.parse()
		expr1 := p.parse()
		expr2 := p.parse()

		return func(fe *functionExecution) (result int64) {
			if expr0(fe) != 0 {
				return expr1(fe)
			} else {
				return expr2(fe)
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
		expr0 := p.parse()
		expr1 := p.parse()

		return func(fe *functionExecution) int64 {
			return expr0(fe) + expr1(fe)
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

type execution struct {
	mem []byte
}

type functionExecution struct {
	e    *execution
	vars []int64
}
