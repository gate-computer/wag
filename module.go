package wag

import (
	"errors"
	"fmt"
	"sort"
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
	Memory          Memory
	Signatures      SignaturesByIndex
	NamedSignatures map[string]*Signature
	Functions       []*Function
	NamedFunctions  map[string]*Function
	Table           []*Function
	Start           string

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
		NamedSignatures: make(map[string]*Signature),
		NamedFunctions:  make(map[string]*Function),
	}

	var sigs []*Signature
	var tableTokens []interface{}

	startSet := false

	for _, x := range top[1:] {
		expr := x.([]interface{})
		name := expr[0].(string)

		var newSig *Signature

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

			i := sort.Search(len(sigs), func(i int) bool {
				return sigs[i].Compare(f.Signature) >= 0
			})
			if i < len(sigs) && sigs[i].Compare(f.Signature) == 0 {
				f.Signature = sigs[i]
			} else {
				newSig = f.Signature
			}

			m.Functions = append(m.Functions, f)

			for _, name := range f.Names {
				m.NamedFunctions[name] = f
			}

		case "start":
			m.Start = expr[1].(string)
			startSet = true

		case "type":
			var sigName string
			newSig, sigName = newSignature(m, expr)
			if sigName != "" {
				m.NamedSignatures[sigName] = newSig
			}

		case "table":
			tableTokens = expr[1:]

		default:
			panic(fmt.Errorf("unknown module child: %s", name))
		}

		if newSig != nil {
			i := sort.Search(len(sigs), func(i int) bool {
				return sigs[i].Compare(newSig) >= 0
			})

			newSig.Index = len(sigs) // in order of appearance

			sigs = append(sigs, nil)
			copy(sigs[i+1:], sigs[i:])
			sigs[i] = newSig
		}
	}

	if !startSet {
		panic(errors.New("start function not defined"))
	}
	if _, found := m.NamedFunctions[m.Start]; !found {
		panic(fmt.Errorf("start function not found: %s", m.Start))
	}

	for _, x := range tableTokens {
		funcName := x.(string)
		f, found := m.NamedFunctions[funcName]
		if !found {
			panic(funcName)
		}
		m.Table = append(m.Table, f)
	}

	m.Signatures = SignaturesByIndex(sigs)
	sort.Sort(m.Signatures)

	return
}

type Memory struct {
	MinSize int
	MaxSize int
}

type Signature struct {
	Index      int
	ArgTypes   []types.T
	ResultType types.T
}

func newSignature(m *Module, list []interface{}) (sig *Signature, name string) {
	f := newFunction(m, list[2].([]interface{}))

	sig = f.Signature
	name = list[1].(string)
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

func (sig1 *Signature) Compare(sig2 *Signature) int {
	len1 := len(sig1.ArgTypes)
	len2 := len(sig2.ArgTypes)

	if len1 < len2 {
		return -1
	}
	if len1 > len2 {
		return 1
	}

	for n := range sig1.ArgTypes {
		arg1 := sig1.ArgTypes[n]
		arg2 := sig2.ArgTypes[n]

		if arg1 < arg2 {
			return -1
		}
		if arg1 > arg2 {
			return 1
		}
	}

	res1 := sig1.ResultType
	res2 := sig2.ResultType

	if res1 < res2 {
		return -1
	}
	if res1 > res2 {
		return 1
	}

	return 0
}

type SignaturesByIndex []*Signature

func (a SignaturesByIndex) Len() int {
	return len(a)
}

func (a SignaturesByIndex) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a SignaturesByIndex) Less(i, j int) bool {
	return a[i].Index < a[j].Index
}

type Var struct {
	Param bool // param or local?
	Index int
	Type  types.T
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
		Signature: &Signature{Index: -1},
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

				v := Var{
					Type: varType,
				}

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
			sig, found := m.NamedSignatures[sigName]
			if !found {
				panic(sigName)
			}

			for _, varType := range sig.ArgTypes {
				numName := strconv.Itoa(f.NumLocals + f.NumParams)

				f.Vars[numName] = Var{
					Param: true,
					Index: f.NumParams,
					Type:  varType,
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
