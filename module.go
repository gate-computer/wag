package wag

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/tsavola/wag/internal/sexp"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
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
	Imports         []*Import
	NamedCallables  map[string]*Callable
	Table           []*Callable
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
		NamedCallables:  make(map[string]*Callable),
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
			args := expr[1:]

			if len(args) > 0 {
				m.Memory.MinSize = int(values.ParseI32(args[0])) << 16
				args = args[1:]
			}

			if len(args) > 0 {
				if _, ok := args[0].(string); ok {
					m.Memory.MaxSize = int(values.ParseI32(args[0])) << 16
					args = args[1:]
				}
			}

			m.Memory.Segments = make([]Segment, len(args))

			for i, arg := range args {
				segment := arg.([]interface{})
				if len(segment) != 3 || segment[0].(string) != "segment" {
					panic(segment)
				}
				offset := int(values.ParseI32(segment[1]))
				data := []byte(segment[2].(string))
				if offset < 0 || offset+len(data) > m.Memory.MinSize {
					panic("data segment out of bounds")
				}
				m.Memory.Segments[i] = Segment{offset, data}
			}

		case "func":
			f := newFunction(m, expr)

			if f.Signature.Index < 0 {
				i := sort.Search(len(sigs), func(i int) bool {
					return sigs[i].Compare(f.Signature) >= 0
				})
				if i < len(sigs) && sigs[i].Compare(f.Signature) == 0 {
					f.Signature = sigs[i]
				} else {
					newSig = f.Signature
				}
			}

			m.Functions = append(m.Functions, f)

			for _, name := range f.Names {
				m.NamedCallables[name] = &f.Callable
			}

		case "start":
			m.Start = expr[1].(string)
			startSet = true

		case "type":
			var sigName string
			newSig, sigName = newSignature(m, expr[1:])
			if sigName != "" {
				m.NamedSignatures[sigName] = newSig
			}

		case "table":
			tableTokens = expr[1:]

		case "import":
			expr = expr[1:]

			var importName string

			if _, ok := expr[2].(string); ok {
				importName = expr[0].(string)
				expr = expr[1:]
			}

			namespace := expr[0].(string)
			name := expr[1].(string)
			newSig = newFunction(m, expr[1:]).Signature

			i := sort.Search(len(sigs), func(i int) bool {
				return sigs[i].Compare(newSig) >= 0
			})
			if i < len(sigs) && sigs[i].Compare(newSig) == 0 {
				newSig = sigs[i]
			}

			im := &Import{
				Callable: Callable{
					Signature: newSig,
				},
				Namespace: namespace,
				Name:      name,
			}
			m.Imports = append(m.Imports, im)

			if importName != "" {
				m.NamedCallables[importName] = &im.Callable
			}

		default:
			panic(fmt.Errorf("unknown module child: %s", name))
		}

		if newSig != nil {
			newSig.Index = len(sigs) // in order of appearance
			m.Signatures = append(m.Signatures, newSig)
			sort.Sort(m.Signatures)

			i := sort.Search(len(sigs), func(i int) bool {
				return sigs[i].Compare(newSig) >= 0
			})
			sigs = append(sigs, nil)
			copy(sigs[i+1:], sigs[i:])
			sigs[i] = newSig
		}
	}

	if !startSet {
		panic(errors.New("start function not defined"))
	}
	if _, found := m.NamedCallables[m.Start]; !found {
		panic(fmt.Errorf("start function not found: %s", m.Start))
	}

	for _, x := range tableTokens {
		funcName := x.(string)
		var c *Callable

		if i, err := strconv.Atoi(funcName); err == nil {
			c = &m.Functions[i].Callable
		} else {
			var found bool
			c, found = m.NamedCallables[funcName]
			if !found {
				panic(funcName)
			}
		}

		c.TableIndexes = append(c.TableIndexes, len(m.Table))
		m.Table = append(m.Table, c)
	}

	return
}

func (m *Module) FuncTypes() (sigs []types.Function) {
	sigs = make([]types.Function, 0, len(m.Imports)+len(m.Functions))

	for _, im := range m.Imports {
		sigs = append(sigs, im.Signature.Function)
	}

	for _, f := range m.Functions {
		sigs = append(sigs, f.Signature.Function)
	}

	return
}

func (m *Module) FuncNames() (names []string) {
	names = make([]string, 0, len(m.Imports)+len(m.Functions))

	for _, im := range m.Imports {
		name := fmt.Sprintf("%s %s", im.Namespace, im.Name)
		names = append(names, name)
	}

	for i, f := range m.Functions {
		var name string
		if len(f.Names) > 0 {
			name = f.Names[0]
		} else {
			name = fmt.Sprintf("unnamed function #%d", i)
		}
		names = append(names, name)
	}

	return
}

func (m *Module) ImportTypes() (sigs map[int64]types.Function) {
	sigs = make(map[int64]types.Function)
	for _, im := range m.Imports {
		sigs[int64(im.Signature.Index)] = im.Signature.Function
	}
	return
}

type Segment struct {
	Offset int
	Data   []byte
}

type Memory struct {
	MinSize  int
	MaxSize  int
	Segments []Segment
}

type Signature struct {
	types.Function
	Index int
}

func newSignature(m *Module, list []interface{}) (sig *Signature, name string) {
	name, ok := list[0].(string)
	if ok {
		list = list[1:]
	}

	sig = newFunction(m, list[0].([]interface{})).Signature
	return
}

func (sig *Signature) String() string {
	return sig.Function.String()
}

func (sig1 *Signature) Compare(sig2 *Signature) int {
	len1 := len(sig1.Args)
	len2 := len(sig2.Args)

	if len1 < len2 {
		return -1
	}
	if len1 > len2 {
		return 1
	}

	for n := range sig1.Args {
		arg1 := sig1.Args[n]
		arg2 := sig2.Args[n]

		if arg1 < arg2 {
			return -1
		}
		if arg1 > arg2 {
			return 1
		}
	}

	res1 := sig1.Result
	res2 := sig2.Result

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

type Callable struct {
	*Signature
	TableIndexes []int
}

func (c *Callable) String() string {
	return c.Signature.String()
}

type Import struct {
	Callable

	Namespace string
	Name      string
}

func (im *Import) String() string {
	return fmt.Sprintf("%s %s %s", im.Namespace, im.Name, &im.Callable)
}

type Function struct {
	Callable

	Names  []string
	Params []types.T
	Locals []types.T
	Vars   map[string]Var

	body []interface{}
}

func newFunction(m *Module, list []interface{}) (f *Function) {
	list = list[1:] // skip "func" token

	f = &Function{
		Callable: Callable{
			Signature: &Signature{Index: -1},
		},
		Vars: make(map[string]Var),
	}

	for len(list) > 0 {
		name, ok := list[0].(string)
		if !ok {
			break
		}

		f.Names = append(f.Names, name)

		list = list[1:]
	}

	var typeName *string

loop:
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
				numName := strconv.Itoa(len(f.Locals) + len(f.Params))

				v := Var{
					Type: varType,
				}

				switch exprName {
				case "local":
					v.Param = false
					v.Index = len(f.Locals)
					f.Locals = append(f.Locals, varType)

				case "param":
					f.Signature.Args = append(f.Signature.Args, varType)

					v.Param = true
					v.Index = len(f.Params)
					f.Params = append(f.Params, varType)
				}

				if varName != "" {
					f.Vars[varName] = v
					varName = ""
				}

				f.Vars[numName] = v
			}

		case "type":
			typeName = new(string)
			*typeName = args[0].(string)

		case "result":
			f.Signature.Result = types.ByString[args[0].(string)]

		default:
			f.body = list[i:]
			break loop
		}
	}

	if typeName != nil {
		var sig *Signature

		if i, err := strconv.Atoi(*typeName); err == nil {
			sig = m.Signatures[i]
		} else {
			var found bool
			sig, found = m.NamedSignatures[*typeName]
			if !found {
				panic(*typeName)
			}
		}

		if len(f.Signature.Args) == 0 && f.Signature.Result == types.Void {
			for i, varType := range sig.Args {
				numName := strconv.Itoa(len(f.Locals) + i)

				f.Vars[numName] = Var{
					Param: true,
					Index: i,
					Type:  varType,
				}

				f.Params = append(f.Params, varType)
			}
		} else if !f.Signature.Equal(sig.Function) {
			panic(fmt.Errorf("%s vs. %s", f.Signature, sig))
		}

		f.Signature = sig
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
