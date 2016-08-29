package wag

import (
	"errors"
	"fmt"

	"github.com/tsavola/wag/ins"
)

const (
	WordSize          = 8
	FunctionAlignment = 16
)

func (mo *Module) GenCode() []byte {
	m := &moduleCodeGen{
		Module:        mo,
		functionStubs: make(map[string]*ins.Stub),
	}

	m.module()

	return m.binary
}

type moduleCodeGen struct {
	*Module
	functionStubs map[string]*ins.Stub
	binary        []byte
}

func (m *moduleCodeGen) module() (binary []byte) {
	for _, f := range m.Functions {
		m.functionStubs[f.Name] = &ins.Stub{Name: f.Name}
	}

	m.function(m.Functions[m.Start])

	for name, f := range m.Functions {
		if name != m.Start {
			m.function(f)
		}
	}

	for _, stub := range m.functionStubs {
		native.UpdateCalls(stub, m.binary)
	}

	return
}

func (m *moduleCodeGen) function(fu *Function) {
	f := functionCodeGen{
		Function: fu,
		m:        m,
	}

	m.functionStubs[f.Name].Address = len(m.binary)

	f.inst(ins.XOR{SourceReg: 0, TargetReg: 0})

	for i := 0; i < f.NumLocals; i++ {
		f.inst(ins.Push{SourceReg: 0})
	}

	for _, x := range f.body {
		f.expr(x)
	}

	if f.stackOffset != 0 {
		panic(errors.New("internal: stack offset is non-zero at end of function"))
	}

	if n := f.NumLocals * WordSize; n > 0 {
		f.inst(ins.AddSP{n})
	}

	f.inst(ins.Ret{})

	for _, stub := range f.branchStubs {
		native.UpdateBranches(stub, m.binary)
	}

	paddingSize := FunctionAlignment - (len(m.binary) & (FunctionAlignment - 1))
	for i := 0; i < paddingSize; i++ {
		m.binary = append(m.binary, native.PaddingByte())
	}
}

type functionCodeGen struct {
	*Function
	m           *moduleCodeGen
	stackOffset int
	branchStubs []*ins.Stub
}

func (f *functionCodeGen) expr(x interface{}) {
	item := x.([]interface{})

	switch item[0].(string) {
	case "call":
		if len(item) < 2 {
			panic(errors.New("call: too few operands"))
		}
		name := item[1].(string)
		target, found := f.m.Functions[name]
		if !found {
			panic(fmt.Errorf("call: function not found: %s", name))
		}
		if len(target.Signature.ArgTypes) != len(item)-2 {
			panic(errors.New("call: wrong number of arguments"))
		}
		args := item[2:]
		for _, arg := range args {
			f.expr(arg)
			f.inst(ins.Push{SourceReg: 0})
			f.stackOffset += WordSize
		}
		f.inst(ins.Call{Target: f.m.functionStubs[target.Name]})
		for range args {
			f.inst(ins.Pop{TargetReg: 1})
			f.stackOffset -= WordSize
		}

	case "get_local":
		if len(item) != 2 {
			panic(errors.New("get_local: wrong number of operands"))
		}
		name := item[1].(string)
		offset, found := f.getVarOffset(name)
		if !found {
			panic(fmt.Errorf("get_local: variable not found: %s", name))
		}
		f.inst(ins.MovVarToReg{SourceOffset: f.stackOffset + offset, TargetReg: 0})

	case "i32.add":
		if len(item) != 3 {
			panic(errors.New("add: wrong number of operands"))
		}
		f.expr(item[1])
		f.inst(ins.Push{SourceReg: 0})
		f.stackOffset += WordSize
		f.expr(item[2])
		f.inst(ins.MovRegToReg{SourceReg: 0, TargetReg: 1})
		f.inst(ins.Pop{TargetReg: 0})
		f.stackOffset -= WordSize
		f.inst(ins.Add{Type: ins.TypeI32, SourceReg: 1, TargetReg: 0})

	case "i32.const":
		if len(item) != 2 {
			panic(errors.New("const: wrong number of operands"))
		}
		f.inst(ins.MovImmToReg{Type: ins.TypeI32, SourceImm: item[1], TargetReg: 0})

	case "i32.ne":
		if len(item) != 3 {
			panic(errors.New("ne: wrong number of operands"))
		}
		f.expr(item[1])
		f.inst(ins.Push{SourceReg: 0})
		f.stackOffset += WordSize
		f.expr(item[2])
		f.inst(ins.MovRegToReg{SourceReg: 0, TargetReg: 1})
		f.inst(ins.Pop{TargetReg: 0})
		f.stackOffset -= WordSize
		f.inst(ins.NE{Type: ins.TypeI32, SourceReg: 1, TargetReg: 0, ScratchReg: 2})

	case "i32.sub":
		if len(item) != 3 {
			panic(errors.New("add: wrong number of operands"))
		}
		f.expr(item[1])
		f.inst(ins.Push{SourceReg: 0})
		f.stackOffset += WordSize
		f.expr(item[2])
		f.inst(ins.MovRegToReg{SourceReg: 0, TargetReg: 1})
		f.inst(ins.Pop{TargetReg: 0})
		f.stackOffset -= WordSize
		f.inst(ins.Sub{Type: ins.TypeI32, SourceReg: 1, TargetReg: 0})

	case "if":
		if len(item) < 3 {
			panic(errors.New("if: too few operands"))
		}
		haveElse := len(item) == 4
		if len(item) > 4 {
			panic(errors.New("if: too many operands"))
		}
		afterThen := new(ins.Stub)
		afterElse := new(ins.Stub)
		f.expr(item[1])
		f.inst(ins.BrIfNot{Reg: 0, Target: afterThen})
		for _, e := range item[2].([]interface{}) {
			f.expr(e)
		}
		if haveElse {
			f.inst(ins.Br{Target: afterElse})
		}
		f.inst(ins.Label{afterThen})
		if haveElse {
			for _, e := range item[3].([]interface{}) {
				f.expr(e)
			}
			f.inst(ins.Label{afterElse})
		}

	case "return":
		if f.Signature.ResultType == ins.TypeVoid {
			if len(item) != 1 {
				panic(errors.New("return: wrong number of operands"))
			}
		} else {
			if len(item) != 2 {
				panic(errors.New("return: wrong number of operands"))
			}
			f.expr(item[1])
		}
		if n := f.stackOffset + f.NumLocals*WordSize; n > 0 {
			f.inst(ins.AddSP{n})
		}
		f.inst(ins.Ret{})

	default:
		fmt.Printf("expression not supported: %v\n", item)
		f.inst(ins.Invalid{})
	}
}

func (f *functionCodeGen) inst(x interface{}) {
	b := native.Encode(x)
	f.m.binary = append(f.m.binary, b...)
	pos := len(f.m.binary)

	switch x := x.(type) {
	case ins.Br:
		x.Target.Sites = append(x.Target.Sites, pos)
		f.branchStubs = append(f.branchStubs, x.Target)

	case ins.BrIfNot:
		x.Target.Sites = append(x.Target.Sites, pos)
		f.branchStubs = append(f.branchStubs, x.Target)

	case ins.Call:
		x.Target.Sites = append(x.Target.Sites, pos)

	case ins.Label:
		x.Stub.Address = pos
	}
}
