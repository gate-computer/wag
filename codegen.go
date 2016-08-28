package wag

import (
	"errors"
	"fmt"

	"github.com/tsavola/wag/ins"
)

const (
	WordSize          = 8
	FunctionAlignment = 16
	BaseAddress       = 0x40000
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

	return
}

func (code *moduleCodeGen) binaryFunction(binary []byte, name string, assembly []interface{}) []byte {
	fmt.Println("FUNCTION BINARY:", name)

	code.stubs[name].Address = uint64(BaseAddress + len(binary))

	for _, inst := range assembly {
		b := native.Encode(inst)
		fmt.Printf("\t%v\n", b)

		binary = append(binary, b...)
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
	fmt.Println("FUNCTION ASSEMBLY:", f)

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

	for i := 0; i < f.NumLocals; i++ {
		code.inst(ins.Pop{TargetReg: 1})
	}

	code.inst(ins.Ret{})

	code.functions[f.Name] = code.assembly

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
	case "i32.add":
		if len(item) != 3 {
			panic(errors.New("add: wrong number of operands"))
		}
		code.expr(item[1].([]interface{}))
		code.inst(ins.Push{SourceReg: 0})
		code.offset += WordSize
		code.expr(item[2].([]interface{}))
		code.inst(ins.MovRegToReg{SourceReg: 0, TargetReg: 1})
		code.inst(ins.Pop{TargetReg: 0})
		code.offset -= WordSize
		code.inst(ins.Add{Type: ins.TypeI32, SourceReg: 1, TargetReg: 0})

	case "i32.const":
		if len(item) != 2 {
			panic(errors.New("get_local: wrong number of operands"))
		}
		code.inst(ins.MovImmToReg{Type: ins.TypeI32, SourceImm: item[1], TargetReg: 0})

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
			code.expr(arg.([]interface{}))
			code.inst(ins.Push{SourceReg: 0})
			code.offset += WordSize
		}
		code.inst(ins.Call{Function: code.stubs[target.Name]})
		for range args {
			code.inst(ins.Pop{TargetReg: 1})
			code.offset -= WordSize
		}
	}
}

func (code *codeGen) inst(x interface{}) {
	code.assembly = append(code.assembly, x)
}
