package wag

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tsavola/wag/ins"
	"github.com/tsavola/wag/sexp"
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

	m = loadModule(data)
	return
}

func loadModule(data []byte) (m *Module) {
	top := sexp.ParsePanic(data)

	fmt.Println(sexp.Stringify(top))

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
	ArgTypes   []ins.Type
	ResultType ins.Type
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
			f.Signature.ArgTypes = append(f.Signature.ArgTypes, ins.Types[item[2].(string)])

			f.Params[item[1].(string)] = f.NumParams
			f.NumParams++

		case "result":
			f.Signature.ResultType = ins.Types[item[1].(string)]

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

func (f *Function) getVarOffset(name string) (offset int, found bool) {
	num, found := f.Locals[name]
	if !found {
		num, found = f.Params[name]
		if found {
			// function's return address is between locals and params
			num = f.NumLocals + 1 + (f.NumParams - num - 1)
		}
	}
	offset = num * WordSize
	return
}

func (f *Function) String() string {
	return fmt.Sprintf("%s%s", f.Name, f.Signature)
}
