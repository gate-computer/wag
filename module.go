package wag

import (
	"fmt"
	"strconv"
	"strings"
)

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

func (m *Module) NewExecution() (e *Execution, err error) {
	e = &Execution{
		mem: make([]byte, m.Memory.MinSize),
	}
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
		p := functionParser{loader{l.data(bodySize)}}
		f.expr = p.parse()
	}

	return
}

func (f *Function) Execute(e *Execution, args []int64) (result int64, err error) {
	defer func() {
		if x := recover(); x != nil {
			err = asError(x)
		}
	}()

	result = f.execute(e, args)
	return
}

func (f *Function) execute(e *Execution, args []int64) int64 {
	fe := functionExecution{
		e:    e,
		vars: args,
	}

	return f.expr(&fe)
}

func (f *Function) String() string {
	return fmt.Sprintf("%s %s", f.Flags, f.Signature)
}
