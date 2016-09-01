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

	code.mach.Align()

	program.functionLinks[f].Address = code.mach.Len()

	if f.NumLocals > 0 {
		code.mach.BinaryOp("xor", types.I64, regs.R1, regs.R1)

		for i := 0; i < f.NumLocals; i++ {
			code.mach.OpPush(types.I64, regs.R1)
		}
	}

	var finalType types.T

	for i, x := range f.body {
		var expectType types.T

		if i == len(f.body)-1 {
			expectType = f.Signature.ResultType
		}

		if expectType == types.Void {
			expectType = types.Any
		}

		finalType = code.expr(x, expectType)
	}

	if f.Signature.ResultType != types.Void && finalType != f.Signature.ResultType {
		panic(fmt.Errorf("last expression of function %s returns incorrect type: %s", f, finalType))
	}

	if code.stackOffset != 0 {
		panic(errors.New("internal: stack offset is non-zero at end of function"))
	}

	if offset := code.getLocalsEndOffset(); offset > 0 {
		code.mach.OpAddToStackPtr(offset) // don't update stackOffset
	}

	code.mach.OpReturn()

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

func (code *functionCoder) expr(x interface{}, expectType types.T) (resultType types.T) {
	expr := x.([]interface{})
	exprName := expr[0].(string)
	args := expr[1:]

	if strings.Contains(exprName, ".") {
		tokens := strings.SplitN(exprName, ".", 2)

		opType, found := types.ByString[tokens[0]]
		if !found {
			panic(fmt.Errorf("unknown operand type: %s", exprName))
		}

		opName := tokens[1]
		resultType = opType

		switch opName {
		case "eqz":
			resultType = types.I32
			fallthrough

		case "neg":
			if len(args) != 1 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.expr(args[0], opType)
			code.mach.UnaryOp(opName, opType, regs.R0)

		case "ne":
			resultType = types.I32
			fallthrough

		case "add", "and", "or", "sub", "xor":
			if len(args) != 2 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.expr(args[0], opType)
			code.opPush(opType, regs.R0)
			code.expr(args[1], opType)
			code.mach.OpMove(opType, regs.R0, regs.R1)
			code.opPop(opType, regs.R0)
			code.mach.BinaryOp(opName, opType, regs.R1, regs.R0)

		case "const":
			if len(args) != 1 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.mach.OpMoveImm(opType, args[0], regs.R0)

		default:
			panic(exprName)
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
			funcArgs := args[1:]
			if len(target.Signature.ArgTypes) != len(funcArgs) {
				panic(fmt.Errorf("%s: wrong number of arguments", exprName))
			}
			for i, arg := range funcArgs {
				t := target.Signature.ArgTypes[i]
				code.expr(arg, t)
				code.opPush(t, regs.R0)
			}
			code.opCall(code.program.functionLinks[target])
			if len(funcArgs) > 0 {
				code.opAddToStackPtr(len(funcArgs) * wordSize)
			}
			resultType = target.Signature.ResultType

		case "get_local":
			if len(args) != 1 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			varName := args[0].(string)
			offset, varType, found := code.getVarOffsetAndType(varName)
			if !found {
				panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
			}
			code.mach.OpLoadStack(varType, offset, regs.R0)
			resultType = varType

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
			t := code.expr(args[0], types.AnyScalar)
			code.opBranchIfNot(t, 0, afterThen)
			var thenType types.T
			for _, e := range args[1].([]interface{}) {
				thenType = code.expr(e, types.Any)
			}
			if haveElse {
				code.opBranch(afterElse)
				code.mach.Align()
			}
			code.label(afterThen)
			if haveElse {
				var elseType types.T
				for _, e := range args[2].([]interface{}) {
					elseType = code.expr(e, types.Any)
				}
				code.label(afterElse)
				if thenType != elseType {
					panic(fmt.Errorf("%s: then and else expressions return distinct types: %s vs. %s", exprName, thenType, elseType))
				}
			}
			resultType = thenType

		case "nop":
			if len(args) != 0 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.mach.OpNop()

		case "return":
			if code.function.Signature.ResultType == types.Void {
				if len(args) == 1 {
					code.expr(args[0], types.Void)
				} else if len(args) != 0 {
					panic(fmt.Errorf("%s: wrong number of operands", exprName))
				}
			} else {
				if len(args) != 1 {
					panic(fmt.Errorf("%s: wrong number of operands", exprName))
				}
				code.expr(args[0], code.function.Signature.ResultType)
			}
			if offset := code.getLocalsEndOffset(); offset > 0 {
				code.mach.OpAddToStackPtr(offset)
			}
			code.mach.OpReturn()
			resultType = code.function.Signature.ResultType

		case "unreachable":
			if len(args) != 0 {
				panic(fmt.Errorf("%s: wrong number of operands", exprName))
			}
			code.mach.OpInvalid()
			resultType = expectType

		default:
			panic(exprName)
		}
	}

	switch expectType {
	case types.Any:
		return

	case types.AnyScalar:
		switch resultType {
		case types.I32, types.I64, types.F32, types.F64:
			return
		}

	default:
		if resultType == expectType {
			return
		}
	}

	panic(fmt.Errorf("result type %s does not match expected type %s", resultType, expectType))
}

func (code *functionCoder) opAddToStackPtr(offset int) {
	code.mach.OpAddToStackPtr(offset)
	code.stackOffset -= offset
}

func (code *functionCoder) opBranch(l *links.L) {
	code.mach.StubOpBranch()
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks = append(code.labelLinks, l)
}

func (code *functionCoder) opBranchIfNot(t types.T, reg regs.R, l *links.L) {
	code.mach.StubOpBranchIfNot(t, reg)
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks = append(code.labelLinks, l)
}

func (code *functionCoder) opCall(l *links.L) {
	code.mach.StubOpCall()
	l.Sites = append(l.Sites, code.mach.Len())
}

func (code *functionCoder) opPop(t types.T, reg regs.R) {
	code.mach.OpPop(t, reg)
	code.stackOffset -= wordSize
}

func (code *functionCoder) opPush(t types.T, reg regs.R) {
	code.mach.OpPush(t, reg)
	code.stackOffset += wordSize
}

func (code *functionCoder) label(l *links.L) {
	l.Address = code.mach.Len()
}

func (code *functionCoder) getVarOffsetAndType(name string) (offset int, varType types.T, found bool) {
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
	varType = v.Type
	return
}

func (code *functionCoder) getLocalsEndOffset() int {
	return code.stackOffset + code.function.NumLocals*wordSize
}
