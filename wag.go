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
	Body      []byte
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
		f.Body = l.data(bodySize)
	}

	return
}

func (f *Function) Execute(args []interface{}) (result interface{}, err error) {
	defer func() {
		if x := recover(); x != nil {
			err = asError(x)
		}
	}()

	result = f.execute(args)
	return
}

func (f *Function) execute(args []interface{}) interface{} {
	l := &loader{f.Body}

	for len(args) < len(f.Signature.ArgTypes) {
		args = append(args, nil)
	}

	return execute(l, args)
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
	opI32_Add  = 0x40
	opGetLocal = 0x0e
)

func execute(l *loader, vars []interface{}) (result interface{}) {
	op := l.uint8()

	switch op {
	case opI32_Add:
		a := execute(l, vars).(int32)
		b := execute(l, vars).(int32)
		result = a + b

	case opGetLocal:
		result = vars[l.uint8()]

	default:
		panic(fmt.Errorf("unsupported opcode: %d", op))
	}

	return
}
