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

func (m *Module) GenCode() []byte {
	code := moduleCodeGen{
		m:         m,
		stubs:     make(map[string]*ins.Stub),
		functions: make(map[string][]interface{}),
	}

	code.module()

	return code.binary()
}

func (code *moduleCodeGen) binary() (binary []byte) {
	assembly := code.functions[code.m.Start]
	binary = code.binaryFunction(binary, code.m.Start, assembly)

	for name, assembly := range code.functions {
		if name != code.m.Start {
			binary = code.binaryFunction(binary, name, assembly)
		}
	}

	for _, stub := range code.stubs {
		native.UpdateCalls(stub, binary)
	}

	return
}

func (code *moduleCodeGen) binaryFunction(binary []byte, name string, assembly []interface{}) []byte {
	code.stubs[name].Address = len(binary)

	var branchTargets []*ins.Stub

	for _, inst := range assembly {
		b := native.Encode(inst)
		binary = append(binary, b...)

		switch x := inst.(type) {
		case ins.Br:
			x.Target.Sites = append(x.Target.Sites, len(binary))
			branchTargets = append(branchTargets, x.Target)

		case ins.BrIfNot:
			x.Target.Sites = append(x.Target.Sites, len(binary))
			branchTargets = append(branchTargets, x.Target)

		case ins.Call:
			x.Target.Sites = append(x.Target.Sites, len(binary))

		case ins.Label:
			x.Stub.Address = len(binary)
		}
	}

	for _, stub := range branchTargets {
		native.UpdateBranches(stub, binary)
	}

	paddingSize := FunctionAlignment - (len(binary) & (FunctionAlignment - 1))
	for i := 0; i < paddingSize; i++ {
		binary = append(binary, native.PaddingByte())
	}

	return binary
}

type moduleCodeGen struct {
	m         *Module
	stubs     map[string]*ins.Stub
	functions map[string][]interface{}
}

func (code *moduleCodeGen) module() {
	for _, f := range code.m.Functions {
		code.stubs[f.Name] = &ins.Stub{Name: f.Name}
	}

	for _, f := range code.m.Functions {
		code.function(f)
	}
}

func (parent *moduleCodeGen) function(f *Function) {
	code := codeGen{
		moduleCodeGen: parent,
		f:             f,
	}

	code.inst(ins.XOR{SourceReg: 0, TargetReg: 0})

	for i := 0; i < f.NumLocals; i++ {
		code.inst(ins.Push{SourceReg: 0})
	}

	for _, x := range f.body {
		code.expr(x)
	}

	if code.offset != 0 {
		panic(errors.New("internal: stack offset is non-zero at end of function"))
	}

	if n := f.NumLocals * WordSize; n > 0 || true { // XXX
		code.inst(ins.AddSP{n})
	}

	code.inst(ins.Ret{})

	code.functions[f.Name] = code.assembly

	fmt.Printf("%s:\n", f.Name)
	for _, inst := range code.assembly {
		fmt.Printf("%v\n", inst)
	}
}

type codeGen struct {
	*moduleCodeGen
	f        *Function
	offset   int
	assembly []interface{}
}

func (code *codeGen) expr(x interface{}) {
	item := x.([]interface{})

	switch item[0].(string) {
	case "call":
		if len(item) < 2 {
			panic(errors.New("call: too few operands"))
		}
		name := item[1].(string)
		target, found := code.m.Functions[name]
		if !found {
			panic(fmt.Errorf("call: function not found: %s", name))
		}
		if len(target.Signature.ArgTypes) != len(item)-2 {
			panic(errors.New("call: wrong number of arguments"))
		}
		args := item[2:]
		for _, arg := range args {
			code.expr(arg)
			code.inst(ins.Push{SourceReg: 0})
			code.offset += WordSize
		}
		code.inst(ins.Call{Target: code.stubs[target.Name]})
		for range args {
			code.inst(ins.Pop{TargetReg: 1})
			code.offset -= WordSize
		}

	case "get_local":
		if len(item) != 2 {
			panic(errors.New("get_local: wrong number of operands"))
		}
		name := item[1].(string)
		offset, found := code.f.getVarOffset(name)
		if !found {
			panic(fmt.Errorf("get_local: variable not found: %s", name))
		}
		code.inst(ins.MovVarToReg{SourceOffset: code.offset + offset, TargetReg: 0})

	case "i32.add":
		if len(item) != 3 {
			panic(errors.New("add: wrong number of operands"))
		}
		code.expr(item[1])
		code.inst(ins.Push{SourceReg: 0})
		code.offset += WordSize
		code.expr(item[2])
		code.inst(ins.MovRegToReg{SourceReg: 0, TargetReg: 1})
		code.inst(ins.Pop{TargetReg: 0})
		code.offset -= WordSize
		code.inst(ins.Add{Type: ins.TypeI32, SourceReg: 1, TargetReg: 0})

	case "i32.const":
		if len(item) != 2 {
			panic(errors.New("const: wrong number of operands"))
		}
		code.inst(ins.MovImmToReg{Type: ins.TypeI32, SourceImm: item[1], TargetReg: 0})

	case "i32.ne":
		if len(item) != 3 {
			panic(errors.New("ne: wrong number of operands"))
		}
		code.expr(item[1])
		code.inst(ins.Push{SourceReg: 0})
		code.offset += WordSize
		code.expr(item[2])
		code.inst(ins.MovRegToReg{SourceReg: 0, TargetReg: 1})
		code.inst(ins.Pop{TargetReg: 0})
		code.offset -= WordSize
		code.inst(ins.NE{Type: ins.TypeI32, SourceReg: 1, TargetReg: 0, ScratchReg: 2})

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
		code.expr(item[1])
		code.inst(ins.BrIfNot{Reg: 0, Target: afterThen})
		for _, e := range item[2].([]interface{}) {
			code.expr(e)
		}
		if haveElse {
			code.inst(ins.Br{Target: afterElse})
		}
		code.inst(ins.Label{afterThen})
		if haveElse {
			for _, e := range item[2].([]interface{}) {
				code.expr(e)
			}
			code.inst(ins.Label{afterElse})
		}

	case "return":
		if code.f.Signature.ResultType == ins.TypeVoid {
			if len(item) != 1 {
				panic(errors.New("return: wrong number of operands"))
			}
		} else {
			if len(item) != 2 {
				panic(errors.New("return: wrong number of operands"))
			}
			code.expr(item[1])
		}
		if n := code.offset + code.f.NumLocals*WordSize; n > 0 || true { // XXX
			code.inst(ins.AddSP{n})
		}
		code.inst(ins.Ret{})

	default:
		fmt.Printf("expression not supported: %v\n", item)
		code.inst(ins.Invalid{})
	}
}

func (code *codeGen) inst(x interface{}) {
	code.assembly = append(code.assembly, x)
}
