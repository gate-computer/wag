package wag

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tsavola/wag/internal/sexp"
	"github.com/tsavola/wag/internal/types"
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

var typeMap = map[string]types.Type{
	"void": types.Void,
	"i32":  types.I32,
	"i64":  types.I64,
	"f32":  types.F32,
	"f64":  types.F64,
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
	Memory    Memory
	Functions map[string]*Function
	Start     string

	code []byte
}

func LoadModule(data []byte) (m *Module, err error) {
	defer func() {
		if x := recover(); x != nil {
			if err, _ = x.(error); err == nil {
				panic(x)
			}
		}
	}()

	top, _ := sexp.ParsePanic(data)
	m = loadModule(top)
	return
}

func loadModule(top []interface{}) (m *Module) {
	if s := top[0].(string); s != "module" {
		panic(errors.New("not a module"))
	}

	m = &Module{
		Functions: make(map[string]*Function),
	}

	startSet := false

	for _, x := range top[1:] {
		item := x.([]interface{})
		name := item[0].(string)

		switch name {
		case "memory":
			if len(item) > 1 {
				m.Memory.MinSize = int(item[1].(uint64))
			}
			if len(item) > 2 {
				m.Memory.MaxSize = int(item[2].(uint64))
			}

		case "func":
			f := newFunction(item)
			m.Functions[f.Name] = f

		case "start":
			m.Start = item[1].(string)
			startSet = true

		default:
			panic(fmt.Errorf("unknown module child: %s", name))
		}
	}

	if !startSet {
		panic(errors.New("start function not defined"))
	}
	if _, found := m.Functions[m.Start]; !found {
		panic(fmt.Errorf("start function not found: %s", m.Start))
	}

	return
}

type Memory struct {
	MinSize int
	MaxSize int
}

type Signature struct {
	ArgTypes   []types.Type
	ResultType types.Type
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
	Name      string
	Signature *Signature
	Params    map[string]int
	NumParams int
	Locals    map[string]int
	NumLocals int

	body []interface{}
}

func newFunction(list []interface{}) (f *Function) {
	f = &Function{
		Name:      list[1].(string),
		Signature: &Signature{},
		Params:    make(map[string]int),
		Locals:    make(map[string]int),
	}

	for i, x := range list[2:] {
		item := x.([]interface{})
		name := item[0].(string)

		switch name {
		case "param":
			f.Signature.ArgTypes = append(f.Signature.ArgTypes, typeMap[item[2].(string)])

			f.Params[item[1].(string)] = f.NumParams
			f.NumParams++

		case "result":
			f.Signature.ResultType = typeMap[item[1].(string)]

		case "local":
			f.Params[item[1].(string)] = f.NumLocals
			f.NumLocals++

		default:
			f.body = list[2+i:]
			return
		}
	}

	return
}

func (f *Function) String() string {
	return fmt.Sprintf("%s%s", f.Name, f.Signature)
}
