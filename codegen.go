package wag

import (
	"errors"
	"fmt"

	"github.com/tsavola/wag/internal/stubs"
	"github.com/tsavola/wag/internal/types"
)

const (
	wordSize = 8
)

func (mo *Module) GenCode() []byte {
	m := &moduleCodeGen{
		Module:        mo,
		functionStubs: make(map[string]*stubs.Function),
	}

	m.module()

	return m.binary
}

type moduleCodeGen struct {
	*Module
	functionStubs map[string]*stubs.Function
	binary        []byte
}

func (m *moduleCodeGen) module() (binary []byte) {
	for _, f := range m.Functions {
		m.functionStubs[f.Name] = &stubs.Function{Name: f.Name}
	}

	m.function(m.Functions[m.Start])

	for name, f := range m.Functions {
		if name != m.Start {
			m.function(f)
		}
	}

	for _, stub := range m.functionStubs {
		mach.UpdateCalls(stub, m.binary)
	}

	return
}

func (m *moduleCodeGen) function(fu *Function) {
	f := functionCodeGen{
		Function: fu,
		module:   m,
	}

	m.functionStubs[f.Name].Address = len(m.binary)

	f.inst(mach.XOR(0, 0))

	for i := 0; i < f.NumLocals; i++ {
		f.inst(mach.Push(0))
	}

	for _, x := range f.body {
		f.expr(x)
	}

	if f.stackOffset != 0 {
		panic(errors.New("internal: stack offset is non-zero at end of function"))
	}

	if n := f.NumLocals * wordSize; n > 0 {
		f.inst(mach.AddSP(n))
	}

	f.inst(mach.Ret())

	for _, stub := range f.labelStubs {
		mach.UpdateBranches(stub, m.binary)
	}

	paddingSize := mach.FunctionAlign() - (len(m.binary) & (mach.FunctionAlign() - 1))
	for i := 0; i < paddingSize; i++ {
		m.binary = append(m.binary, mach.PaddingByte())
	}
}

type functionCodeGen struct {
	*Function
	module      *moduleCodeGen
	stackOffset int
	labelStubs  []*stubs.Label
}

func (f *functionCodeGen) expr(x interface{}) {
	item := x.([]interface{})

	switch item[0].(string) {
	case "call":
		if len(item) < 2 {
			panic(errors.New("call: too few operands"))
		}
		name := item[1].(string)
		target, found := f.module.Functions[name]
		if !found {
			panic(fmt.Errorf("call: function not found: %s", name))
		}
		if len(target.Signature.ArgTypes) != len(item)-2 {
			panic(errors.New("call: wrong number of arguments"))
		}
		args := item[2:]
		for _, arg := range args {
			f.expr(arg)
			f.inst(mach.Push(0))
			f.stackOffset += wordSize
		}
		f.instCall(f.module.functionStubs[target.Name])
		for range args {
			f.inst(mach.Pop(1))
			f.stackOffset -= wordSize
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
		f.inst(mach.MovVarToReg(f.stackOffset+offset, 0))

	case "i32.add":
		if len(item) != 3 {
			panic(errors.New("add: wrong number of operands"))
		}
		f.expr(item[1])
		f.inst(mach.Push(0))
		f.stackOffset += wordSize
		f.expr(item[2])
		f.inst(mach.MovRegToReg(0, 1))
		f.inst(mach.Pop(0))
		f.stackOffset -= wordSize
		f.inst(mach.Add(types.I32, 1, 0))

	case "i32.const":
		if len(item) != 2 {
			panic(errors.New("const: wrong number of operands"))
		}
		f.inst(mach.MovImmToReg(types.I32, item[1], 0))

	case "i32.ne":
		if len(item) != 3 {
			panic(errors.New("ne: wrong number of operands"))
		}
		f.expr(item[1])
		f.inst(mach.Push(0))
		f.stackOffset += wordSize
		f.expr(item[2])
		f.inst(mach.MovRegToReg(0, 1))
		f.inst(mach.Pop(0))
		f.stackOffset -= wordSize
		f.inst(mach.NE(types.I32, 1, 0, 2))

	case "i32.sub":
		if len(item) != 3 {
			panic(errors.New("add: wrong number of operands"))
		}
		f.expr(item[1])
		f.inst(mach.Push(0))
		f.stackOffset += wordSize
		f.expr(item[2])
		f.inst(mach.MovRegToReg(0, 1))
		f.inst(mach.Pop(0))
		f.stackOffset -= wordSize
		f.inst(mach.Sub(types.I32, 1, 0))

	case "if":
		if len(item) < 3 {
			panic(errors.New("if: too few operands"))
		}
		haveElse := len(item) == 4
		if len(item) > 4 {
			panic(errors.New("if: too many operands"))
		}
		afterThen := &stubs.Label{}
		afterElse := &stubs.Label{}
		f.expr(item[1])
		f.instBrIfNot(0, afterThen)
		for _, e := range item[2].([]interface{}) {
			f.expr(e)
		}
		if haveElse {
			f.instBr(afterElse)
		}
		f.label(afterThen)
		if haveElse {
			for _, e := range item[3].([]interface{}) {
				f.expr(e)
			}
			f.label(afterElse)
		}

	case "return":
		if f.Signature.ResultType == types.Void {
			if len(item) != 1 {
				panic(errors.New("return: wrong number of operands"))
			}
		} else {
			if len(item) != 2 {
				panic(errors.New("return: wrong number of operands"))
			}
			f.expr(item[1])
		}
		if n := f.stackOffset + f.NumLocals*wordSize; n > 0 {
			f.inst(mach.AddSP(n))
		}
		f.inst(mach.Ret())

	default:
		fmt.Printf("expression not supported: %v\n", item)
		f.inst(mach.Invalid())
	}
}

func (f *functionCodeGen) inst(code []byte) {
	f.module.binary = append(f.module.binary, code...)
}

func (f *functionCodeGen) instBr(stub *stubs.Label) {
	f.inst(mach.BrPlaceholder())
	stub.BranchSites = append(stub.BranchSites, len(f.module.binary))
	f.labelStubs = append(f.labelStubs, stub)
}

func (f *functionCodeGen) instBrIfNot(reg byte, stub *stubs.Label) {
	f.inst(mach.BrIfNotPlaceholder(reg))
	stub.BranchSites = append(stub.BranchSites, len(f.module.binary))
	f.labelStubs = append(f.labelStubs, stub)
}

func (f *functionCodeGen) instCall(stub *stubs.Function) {
	f.inst(mach.CallPlaceholder())
	stub.CallSites = append(stub.CallSites, len(f.module.binary))
}

func (f *functionCodeGen) label(stub *stubs.Label) {
	stub.Address = len(f.module.binary)
}

func (f *functionCodeGen) getVarOffset(name string) (offset int, found bool) {
	num, found := f.Locals[name]
	if !found {
		num, found = f.Params[name]
		if found {
			// function's return address is between locals and params
			num = f.NumLocals + 1 + (f.NumParams - num - 1)
		}
	}
	offset = num * wordSize
	return
}
