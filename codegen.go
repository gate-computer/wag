package wag

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

const (
	wordSize = 8
)

func (mo *Module) GenCode() []byte {
	m := &moduleCodeGen{
		Module:        mo,
		functionLinks: make(map[*Function]*links.L),
		code:          machine.NewCoder(),
	}

	m.module()

	return m.code.Bytes()
}

type moduleCodeGen struct {
	*Module
	functionLinks map[*Function]*links.L
	code          coder
}

func (m *moduleCodeGen) module() {
	code := m.code

	for _, f := range m.FunctionList {
		m.functionLinks[f] = new(links.L)
	}

	start := m.Functions[m.Start]
	m.function(start)

	for _, f := range m.FunctionList {
		if f != start {
			m.function(f)
		}
	}

	for _, link := range m.functionLinks {
		code.UpdateCalls(link)
	}

	return
}

func (m *moduleCodeGen) function(fu *Function) {
	code := m.code

	f := &functionCodeGen{
		Function: fu,
		module:   m,
	}

	m.functionLinks[f.Function].Address = code.Len()

	if f.NumLocals > 0 {
		// TODO: decrement stack pointer and check bounds instead
		code.InstClear(regs.R0)
		for i := 0; i < f.NumLocals; i++ {
			code.InstPush(regs.R0)
		}
	}

	for _, x := range f.body {
		f.expr(x)
	}

	if f.stackOffset != 0 {
		panic(errors.New("internal: stack offset is non-zero at end of function"))
	}

	if offset := f.getLocalsEndOffset(); offset > 0 {
		code.InstAddToStackPtr(offset)
	}

	code.InstRet()

	for _, link := range f.labelLinks {
		code.UpdateBranches(link)
	}
}

type functionCodeGen struct {
	*Function
	module      *moduleCodeGen
	stackOffset int
	labelLinks  []*links.L
}

func (f *functionCodeGen) expr(x interface{}) {
	code := f.module.code

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
			code.InstPush(regs.R0)
			f.stackOffset += wordSize
			f.expr(args[1])
			code.InstMoveRegToReg(regs.R0, regs.R1)
			code.InstPop(regs.R0)
			f.stackOffset -= wordSize
			code.TypedBinaryInst(exprType, instName, regs.R1, regs.R0)

		case "const":
			if len(args) != 1 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.InstMoveImmToReg(exprType, args[0], regs.R0)

		default:
			fmt.Printf("operation not supported: %v\n", exprName)
			code.InstInvalid()
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
				code.InstPush(regs.R0)
				f.stackOffset += wordSize
			}
			f.instCall(f.module.functionLinks[target])
			for range funcArgs {
				code.InstPop(regs.R1)
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
			code.InstMoveVarToReg(offset, regs.R0)

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
				if len(args) == 1 {
					// this should return a void...
					f.expr(args[0])
				} else if len(args) != 0 {
					panic(fmt.Errorf("%s: wrong number of operands", exprName))
				}
			} else {
				if len(args) != 1 {
					panic(fmt.Errorf("%s: wrong number of operands", exprName))
				}
				f.expr(args[0])
			}
			if offset := f.getLocalsEndOffset(); offset > 0 {
				code.InstAddToStackPtr(offset)
			}
			code.InstRet()

		case "unreachable":
			if len(args) != 0 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.InstInvalid()

		default:
			fmt.Printf("operation not supported: %v\n", exprName)
			code.InstInvalid()
		}
	}
}

func (f *functionCodeGen) instBranch(l *links.L) {
	code := f.module.code

	code.InstBranchPlaceholder()
	l.Sites = append(l.Sites, code.Len())
	f.labelLinks = append(f.labelLinks, l)
}

func (f *functionCodeGen) instBranchIfNot(reg regs.R, l *links.L) {
	code := f.module.code

	code.InstBranchIfNotPlaceholder(reg)
	l.Sites = append(l.Sites, code.Len())
	f.labelLinks = append(f.labelLinks, l)
}

func (f *functionCodeGen) instCall(l *links.L) {
	code := f.module.code

	code.InstCallPlaceholder()
	l.Sites = append(l.Sites, code.Len())
}

func (f *functionCodeGen) label(l *links.L) {
	l.Address = f.module.code.Len()
}

func (f *functionCodeGen) getVarOffset(name string) (offset int, found bool) {
	v, found := f.Vars[name]
	if !found {
		return
	}

	index := v.Index

	if v.Param {
		// function's return address is between locals and params
		index = f.NumLocals + 1 + (f.NumParams - index - 1)
	}

	offset = f.stackOffset + index*wordSize
	return
}

func (f *functionCodeGen) getLocalsEndOffset() int {
	return f.stackOffset + f.NumLocals*wordSize
}
