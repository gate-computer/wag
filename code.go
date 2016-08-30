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

func (m *Module) Code() []byte {
	code := programCoder{
		mach:          machine.NewCoder(),
		functionLinks: make(map[*Function]*links.L),
	}

	code.module(m)

	return code.mach.Bytes()
}

type programCoder struct {
	mach          machineCoder
	functionLinks map[*Function]*links.L
}

func (code *programCoder) module(m *Module) {
	for _, f := range m.FunctionList {
		code.functionLinks[f] = new(links.L)
	}

	start := m.Functions[m.Start]
	code.function(m, start)

	for _, f := range m.FunctionList {
		if f != start {
			code.function(m, f)
		}
	}

	for _, link := range code.functionLinks {
		code.mach.UpdateCalls(link)
	}

	return
}

func (program *programCoder) function(m *Module, f *Function) {
	code := functionCoder{
		program:  program,
		module:   m,
		function: f,
		mach:     program.mach,
	}

	program.functionLinks[f].Address = code.mach.Len()

	if f.NumLocals > 0 {
		// TODO: decrement stack pointer and check bounds instead
		code.mach.InstClear(regs.R0)
		for i := 0; i < f.NumLocals; i++ {
			code.mach.InstPush(regs.R0)
		}
	}

	for _, x := range f.body {
		code.expr(x)
	}

	if code.stackOffset != 0 {
		panic(errors.New("internal: stack offset is non-zero at end of function"))
	}

	if offset := code.getLocalsEndOffset(); offset > 0 {
		code.mach.InstAddToStackPtr(offset)
	}

	code.mach.InstRet()

	for _, link := range code.labelLinks {
		code.mach.UpdateBranches(link)
	}
}

type functionCoder struct {
	module      *Module
	program     *programCoder
	function    *Function
	mach        machineCoder
	stackOffset int
	labelLinks  []*links.L
}

func (code *functionCoder) expr(x interface{}) {
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
			code.expr(args[0])
			code.mach.InstPush(regs.R0)
			code.stackOffset += wordSize
			code.expr(args[1])
			code.mach.InstMoveRegToReg(regs.R0, regs.R1)
			code.mach.InstPop(regs.R0)
			code.stackOffset -= wordSize
			code.mach.TypedBinaryInst(exprType, instName, regs.R1, regs.R0)

		case "const":
			if len(args) != 1 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.mach.InstMoveImmToReg(exprType, args[0], regs.R0)

		default:
			fmt.Printf("operation not supported: %v\n", exprName)
			code.mach.InstInvalid()
		}
	} else {
		switch exprName {
		case "call":
			if len(args) < 1 {
				panic(fmt.Errorf("%s: too few operands", exprName))
			}
			funcName := args[0].(string)
			target, found := code.module.Functions[funcName]
			if !found {
				panic(fmt.Errorf("%s: function not found: %s", exprName, funcName))
			}
			if len(target.Signature.ArgTypes) != len(args)-1 {
				panic(fmt.Errorf("%s: wrong number of arguments", exprName))
			}
			funcArgs := args[1:]
			for _, arg := range funcArgs {
				code.expr(arg)
				code.mach.InstPush(regs.R0)
				code.stackOffset += wordSize
			}
			code.instCall(code.program.functionLinks[target])
			for range funcArgs {
				code.mach.InstPop(regs.R1)
				code.stackOffset -= wordSize
			}

		case "get_local":
			if len(args) != 1 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			varName := args[0].(string)
			offset, found := code.getVarOffset(varName)
			if !found {
				panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
			}
			code.mach.InstMoveVarToReg(offset, regs.R0)

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
			code.expr(args[0])
			code.instBranchIfNot(0, afterThen)
			for _, e := range args[1].([]interface{}) {
				code.expr(e)
			}
			if haveElse {
				code.instBranch(afterElse)
			}
			code.label(afterThen)
			if haveElse {
				for _, e := range args[2].([]interface{}) {
					code.expr(e)
				}
				code.label(afterElse)
			}

		case "return":
			if code.function.Signature.ResultType == types.Void {
				if len(args) == 1 {
					// this should return a void...
					code.expr(args[0])
				} else if len(args) != 0 {
					panic(fmt.Errorf("%s: wrong number of operands", exprName))
				}
			} else {
				if len(args) != 1 {
					panic(fmt.Errorf("%s: wrong number of operands", exprName))
				}
				code.expr(args[0])
			}
			if offset := code.getLocalsEndOffset(); offset > 0 {
				code.mach.InstAddToStackPtr(offset)
			}
			code.mach.InstRet()

		case "unreachable":
			if len(args) != 0 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.mach.InstInvalid()

		default:
			fmt.Printf("operation not supported: %v\n", exprName)
			code.mach.InstInvalid()
		}
	}
}

func (code *functionCoder) instBranch(l *links.L) {
	code.mach.InstBranchPlaceholder()
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks = append(code.labelLinks, l)
}

func (code *functionCoder) instBranchIfNot(reg regs.R, l *links.L) {
	code.mach.InstBranchIfNotPlaceholder(reg)
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks = append(code.labelLinks, l)
}

func (code *functionCoder) instCall(l *links.L) {
	code.mach.InstCallPlaceholder()
	l.Sites = append(l.Sites, code.mach.Len())
}

func (code *functionCoder) label(l *links.L) {
	l.Address = code.mach.Len()
}

func (code *functionCoder) getVarOffset(name string) (offset int, found bool) {
	v, found := code.function.Vars[name]
	if !found {
		return
	}

	index := v.Index

	if v.Param {
		// function's return address is between locals and params
		index = code.function.NumLocals + 1 + (code.function.NumParams - index - 1)
	}

	offset = code.stackOffset + index*wordSize
	return
}

func (code *functionCoder) getLocalsEndOffset() int {
	return code.stackOffset + code.function.NumLocals*wordSize
}
