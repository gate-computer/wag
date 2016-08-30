package wag

import (
	"errors"
	"fmt"
	"strconv"
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
	Memory       Memory
	Signatures   map[string]*Signature
	FunctionList []*Function
	Functions    map[string]*Function
	Start        string

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
		Signatures: make(map[string]*Signature),
		Functions:  make(map[string]*Function),
	}

	startSet := false

	for _, x := range top[1:] {
		expr := x.([]interface{})
		name := expr[0].(string)

		switch name {
		case "memory":
			if len(expr) > 1 {
				m.Memory.MinSize = int(expr[1].(uint64))
			}
			if len(expr) > 2 {
				m.Memory.MaxSize = int(expr[2].(uint64))
			}

		case "func":
			f := newFunction(m, expr)
			m.FunctionList = append(m.FunctionList, f)
			for _, name := range f.Names {
				m.Functions[name] = f
			}

		case "start":
			m.Start = expr[1].(string)
			startSet = true

		case "type":
			sig := newSignature(m, expr)
			m.Signatures[sig.Name] = sig

		case "table":
			// TODO

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
	Name       string
	ArgTypes   []types.T
	ResultType types.T
}

func newSignature(m *Module, list []interface{}) (sig *Signature) {
	f := newFunction(m, list[2].([]interface{}))

	sig = f.Signature
	sig.Name = list[1].(string)

	return
}

func (sig *Signature) String() (s string) {
	s = sig.Name + "("
	for i, t := range sig.ArgTypes {
		if i > 0 {
			s += ","
		}
		s += t.String()
	}
	s += ")->" + sig.ResultType.String()
	return
}

type Var struct {
	Param bool // param or local?
	Index int
}

type Function struct {
	Names     []string
	Signature *Signature
	NumLocals int
	NumParams int
	Vars      map[string]Var

	body []interface{}
}

func newFunction(m *Module, list []interface{}) (f *Function) {
	list = list[1:] // skip "func" token

	f = &Function{
		Signature: &Signature{},
		Vars:      make(map[string]Var),
	}

	for len(list) > 0 {
		name, ok := list[0].(string)
		if !ok {
			break
		}

		f.Names = append(f.Names, name)

		list = list[1:]
	}

	for i, x := range list {
		expr := x.([]interface{})
		exprName := expr[0].(string)
		args := expr[1:]

		switch exprName {
		case "local", "param":
			var varName string

			if len(args) > 0 {
				s := args[0].(string)
				if strings.HasPrefix(s, "$") {
					varName = s
					args = args[1:]
				}
			}

			var varTypes []types.T

			for len(args) > 0 {
				s := args[0].(string)
				t, found := types.ByString[s]
				if !found {
					panic(s)
				}
				varTypes = append(varTypes, t)
				args = args[1:]
			}

			for _, varType := range varTypes {
				numName := strconv.Itoa(f.NumLocals + f.NumParams)

				var v Var

				switch exprName {
				case "local":
					v.Param = false
					v.Index = f.NumLocals
					f.NumLocals++

				case "param":
					f.Signature.ArgTypes = append(f.Signature.ArgTypes, varType)

					v.Param = true
					v.Index = f.NumParams
					f.NumParams++
				}

				if varName != "" {
					f.Vars[varName] = v
					varName = ""
				}

				f.Vars[numName] = v
			}

		case "type":
			sigName := args[0].(string)
			sig, found := m.Signatures[sigName]
			if !found {
				panic(sigName)
			}

			for range sig.ArgTypes {
				numName := strconv.Itoa(f.NumLocals + f.NumParams)

				f.Vars[numName] = Var{
					Param: true,
					Index: f.NumParams,
				}

				f.NumParams++
			}

			f.Signature.ArgTypes = append(f.Signature.ArgTypes, sig.ArgTypes...)
			f.Signature.ResultType = sig.ResultType

		case "result":
			f.Signature.ResultType = types.ByString[args[0].(string)]

		default:
			f.body = list[i:]
			return
		}
	}

	return
}

func (f *Function) String() string {
	var name string
	if len(f.Names) > 0 {
		name = f.Names[0]
	}
	return fmt.Sprintf("%s%s", name, f.Signature)
}
