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

	functionFlagMask = FunctionFlagName | FunctionFlagImport | FunctionFlagLocals | FunctionFlagExport
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

	if extra := flags &^ functionFlagMask; extra != 0 {
		tokens = append(tokens, fmt.Sprintf("0x%02x", int(extra)))
	}

	return strings.Join(tokens, "|")
}

type Module struct {
	Memory        Memory
	Signatures    []Signature
	Functions     []Function
	FunctionTable []uint16
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
			m.Functions = make([]Function, num)
			for i := 0; i < num; i++ {
				m.Functions[i].load(l, m)
			}
			for i := 0; i < num; i++ {
				m.Functions[i].parse(m)
			}

		case sectionFunctionTable:
			num := l.leb128size()
			m.FunctionTable = make([]uint16, num)
			for i := 0; i < num; i++ {
				m.FunctionTable[i] = l.uint16()
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
	Flags       FunctionFlags
	Signature   *Signature
	NumLocalI32 int
	NumLocalI64 int
	NumLocalF32 int
	NumLocalF64 int

	body []byte
	expr func(*functionExecution) int64
}

func (f *Function) load(l *loader, m *Module) {
	f.Flags = FunctionFlags(l.uint8())

	sigIndex := int(l.uint16())
	if sigIndex >= len(m.Signatures) {
		panic(fmt.Errorf("function signature index out of bounds: %d", sigIndex))
	}
	f.Signature = &m.Signatures[sigIndex]

	l.uint32() // name offset

	if f.Flags&FunctionFlagLocals != 0 {
		f.NumLocalI32 = int(l.uint16())
		f.NumLocalI64 = int(l.uint16())
		f.NumLocalF32 = int(l.uint16())
		f.NumLocalF64 = int(l.uint16())
	}

	if f.Flags&FunctionFlagImport == 0 {
		bodySize := int(l.uint16())
		f.body = l.data(bodySize)
	}
}

func (f *Function) parse(m *Module) {
	if f.body != nil {
		p := functionParser{
			loader: loader{f.body},
			m:      m,
		}

		f.expr = p.parse()
		f.body = nil
	}
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
	numLocals := f.NumLocalI32 + f.NumLocalI64 + f.NumLocalF32 + f.NumLocalF64

	fe := functionExecution{
		e:      e,
		locals: make([]int64, numLocals),
	}

	copy(fe.locals, args)

	return f.expr(&fe)
}

func (f *Function) String() string {
	return fmt.Sprintf("%s %s", f.Flags, f.Signature)
}
