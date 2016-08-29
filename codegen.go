package wag

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/types"
)

const (
	wordSize = 8
)

func (mo *Module) GenCode() []byte {
	m := &moduleCodeGen{
		Module:        mo,
		functionLinks: make(map[*Function]*links.L),
	}

	m.module()

	return m.binary
}

type moduleCodeGen struct {
	*Module
	functionLinks map[*Function]*links.L
	binary        []byte
}

func (m *moduleCodeGen) module() (binary []byte) {
	for _, f := range m.Functions {
		m.functionLinks[f] = new(links.L)
	}

	m.function(m.Functions[m.Start])

	for name, f := range m.Functions {
		if name != m.Start {
			m.function(f)
		}
	}

	for _, link := range m.functionLinks {
		mach.UpdateCalls(link, m.binary)
	}

	return
}

func (m *moduleCodeGen) function(fu *Function) {
	f := functionCodeGen{
		Function: fu,
		module:   m,
	}

	m.functionLinks[f.Function].Address = len(m.binary)

	f.inst(mach.Clear(0))

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
		f.inst(mach.AddToStackPtr(n))
	}

	f.inst(mach.Ret())

	for _, link := range f.labelLinks {
		mach.UpdateBranches(link, m.binary)
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
	labelLinks  []*links.L
}

func (f *functionCodeGen) expr(x interface{}) {
	expr := x.([]interface{})
	exprName := expr[0].(string)
	args := expr[1:]

	if strings.Contains(exprName, ".") {
		tokens := strings.SplitN(exprName, ".", 2)

		exprType, found := types.ByString[tokens[0]]
		if !found {
			panic(fmt.Errorf("unknown operand type: %s", exprName))
		}

		instName := tokens[1]

		switch instName {
		case "add", "and", "ne", "or", "sub", "xor":
			if len(args) != 2 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			f.expr(args[0])
			f.inst(mach.Push(0))
			f.stackOffset += wordSize
			f.expr(args[1])
			f.inst(mach.MoveRegToReg(0, 1))
			f.inst(mach.Pop(0))
			f.stackOffset -= wordSize
			f.inst(mach.TypedBinaryInst(exprType, instName, 1, 0, 2))

		case "const":
			if len(args) != 1 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			f.inst(mach.MoveImmToReg(exprType, args[0], 0))

		default:
			fmt.Printf("operation not supported: %v\n", exprName)
			f.inst(mach.Invalid())
		}
	} else {
		switch exprName {
		case "call":
			if len(args) < 1 {
				panic(fmt.Errorf("%s: too few operands", exprName))
			}
			funcName := args[0].(string)
			target, found := f.module.Functions[funcName]
			if !found {
				panic(fmt.Errorf("%s: function not found: %s", exprName, funcName))
			}
			if len(target.Signature.ArgTypes) != len(args)-1 {
				panic(fmt.Errorf("%s: wrong number of arguments", exprName))
			}
			funcArgs := args[1:]
			for _, arg := range funcArgs {
				f.expr(arg)
				f.inst(mach.Push(0))
				f.stackOffset += wordSize
			}
			f.instCall(f.module.functionLinks[target])
			for range funcArgs {
				f.inst(mach.Pop(1))
				f.stackOffset -= wordSize
			}

		case "get_local":
			if len(args) != 1 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			varName := args[0].(string)
			offset, found := f.getVarOffset(varName)
			if !found {
				panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
			}
			f.inst(mach.MoveVarToReg(f.stackOffset+offset, 0))

		case "if":
			if len(args) < 2 {
				panic(fmt.Errorf("%s: too few operands", exprName))
			}
			haveElse := len(args) == 3
			if len(args) > 3 {
				panic(fmt.Errorf("%s: too many operands", exprName))
			}
			afterThen := new(links.L)
			afterElse := new(links.L)
			f.expr(args[0])
			f.instBranchIfNot(0, afterThen)
			for _, e := range args[1].([]interface{}) {
				f.expr(e)
			}
			if haveElse {
				f.instBranch(afterElse)
			}
			f.label(afterThen)
			if haveElse {
				for _, e := range args[2].([]interface{}) {
					f.expr(e)
				}
				f.label(afterElse)
			}

		case "return":
			if f.Signature.ResultType == types.Void {
				if len(args) != 0 {
					panic(fmt.Errorf("%s: wrong number of operands", exprName))
				}
			} else {
				if len(args) != 1 {
					panic(fmt.Errorf("%s: wrong number of operands", exprName))
				}
				f.expr(args[0])
			}
			if n := f.stackOffset + f.NumLocals*wordSize; n > 0 {
				f.inst(mach.AddToStackPtr(n))
			}
			f.inst(mach.Ret())

		default:
			fmt.Printf("operation not supported: %v\n", exprName)
			f.inst(mach.Invalid())
		}
	}
}

func (f *functionCodeGen) inst(code []byte) {
	f.module.binary = append(f.module.binary, code...)
}

func (f *functionCodeGen) instBranch(l *links.L) {
	f.inst(mach.BranchPlaceholder())
	l.Sites = append(l.Sites, len(f.module.binary))
	f.labelLinks = append(f.labelLinks, l)
}

func (f *functionCodeGen) instBranchIfNot(reg byte, l *links.L) {
	f.inst(mach.BranchIfNotPlaceholder(reg))
	l.Sites = append(l.Sites, len(f.module.binary))
	f.labelLinks = append(f.labelLinks, l)
}

func (f *functionCodeGen) instCall(l *links.L) {
	f.inst(mach.CallPlaceholder())
	l.Sites = append(l.Sites, len(f.module.binary))
}

func (f *functionCodeGen) label(l *links.L) {
	l.Address = len(f.module.binary)
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
