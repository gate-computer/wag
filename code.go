package wag

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
)

const (
	wordSize = 8
)

func (m *Module) Code() (text, roData, data []byte, bssSize int) {
	code := programCoder{
		mach: machine.NewCoder(),
	}

	code.module(m)

	roData = code.roData.populate()

	text = code.mach.Bytes()
	return
}

type programCoder struct {
	mach          machineCoder
	roData        dataArena
	functionLinks map[*Function]*links.L

	trapIndirectCallIndex     links.L
	trapIndirectCallSignature links.L
}

func (code *programCoder) module(m *Module) {
	code.functionLinks = make(map[*Function]*links.L)

	for _, f := range m.Functions {
		code.functionLinks[f] = new(links.L)
	}

	if len(m.Table) > 0 {
		alloc, addr := code.roData.allocate(len(m.Table) * 8)
		if addr != 0 {
			panic(addr)
		}

		alloc.populator = func(data []byte) {
			for _, f := range m.Table {
				if f.Signature.Index < 0 {
					panic("function signature has no index while populating table")
				}

				addr := uint32(code.functionLinks[f].Address)
				sigId := uint32(f.Signature.Index)
				packed := (uint64(sigId) << 32) | uint64(addr)
				machine.ByteOrder().PutUint64(data[:8], packed)
				data = data[8:]
			}
		}
	}

	start := m.NamedFunctions[m.Start]
	code.function(m, start)

	for _, f := range m.Functions {
		if f != start {
			code.function(m, f)
		}
	}

	code.trap(&code.trapIndirectCallIndex, traps.IndirectCallIndex)
	code.trap(&code.trapIndirectCallSignature, traps.IndirectCallSignature)

	for _, link := range code.functionLinks {
		code.mach.UpdateCalls(link)
	}
}

func (program *programCoder) function(m *Module, f *Function) {
	code := functionCoder{
		program:    program,
		module:     m,
		function:   f,
		mach:       program.mach,
		labelLinks: make(map[*links.L]struct{}),
	}

	code.mach.Align()

	program.functionLinks[f].Address = code.mach.Len()

	if f.NumLocals > 0 {
		code.mach.BinaryOp("xor", types.I64, regs.R1, regs.R1)

		for i := 0; i < f.NumLocals; i++ {
			code.mach.OpPush(types.I64, regs.R1)
		}
	}

	expectType := f.Signature.ResultType
	if expectType == types.Void {
		expectType = types.Any
	}

	end := new(links.L)
	code.pushTarget(end, expectType)

	var finalType types.T

	for i, x := range f.body {
		t := types.Any
		if i == len(f.body)-1 {
			t = expectType
		}
		finalType = code.expr(x, t)
	}

	if f.Signature.ResultType != types.Void && finalType != f.Signature.ResultType {
		panic(fmt.Errorf("last expression of function %s returns incorrect type: %s", f, finalType))
	}

	code.popTarget()
	code.label(end)

	if code.stackOffset != 0 {
		panic(errors.New("internal: stack offset is non-zero at end of function"))
	}

	if len(code.targetStack) != 0 {
		panic(errors.New("internal: branch target stack is not empty at end of function"))
	}

	code.opAddToStackPtr(code.getLocalsEndOffset())
	code.mach.OpReturn()

	for link := range code.labelLinks {
		code.mach.UpdateBranches(link)
	}
}

func (code *programCoder) trap(l *links.L, arg int) {
	code.mach.Align()
	l.Address = code.mach.Len()
	code.mach.OpTrap(arg)

	code.mach.UpdateBranches(l)
}

func (code *programCoder) opTrapIfOutOfBounds(indexReg regs.R, upperBound int, trap *links.L) {
	code.mach.StubOpBranchIfOutOfBounds(indexReg, upperBound)
	trap.Sites = append(trap.Sites, code.mach.Len())
}

func (code *programCoder) opTrapIfNotEqualImmTrash(t types.T, value int, subject regs.R, trap *links.L) {
	code.mach.StubOpBranchIfNotEqualImmTrash(t, value, subject)
	trap.Sites = append(trap.Sites, code.mach.Len())
}

type branchTarget struct {
	label       *links.L
	expectType  types.T
	stackOffset int
}

type functionCoder struct {
	module      *Module
	program     *programCoder
	function    *Function
	mach        machineCoder
	stackOffset int
	targetStack []*branchTarget
	labelLinks  map[*links.L]struct{}
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
			code.exprUnaryOp(exprName, opName, opType, args)

		case "ne":
			resultType = types.I32
			fallthrough
		case "add", "and", "or", "sub", "xor":
			code.exprBinaryOp(exprName, opName, opType, args)

		case "const":
			code.exprConst(exprName, opType, args)

		default:
			panic(exprName)
		}
	} else {
		switch exprName {
		case "block":
			resultType = code.exprBlock(exprName, args, expectType)

		case "br", "br_if", "br_table":
			resultType = code.exprBr(exprName, args)

		case "call":
			resultType = code.exprCall(exprName, args)

		case "call_indirect":
			resultType = code.exprCallIndirect(exprName, args)

		case "get_local":
			resultType = code.exprGetLocal(exprName, args)

		case "if":
			resultType = code.exprIf(exprName, args)

		case "nop":
			resultType = code.exprNop(exprName, args)

		case "return":
			resultType = code.exprReturn(exprName, args)

		case "unreachable":
			resultType = code.exprUnreachable(exprName, args, expectType)

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

func (code *functionCoder) exprUnaryOp(exprName, opName string, opType types.T, args []interface{}) {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	code.expr(args[0], opType)
	code.mach.UnaryOp(opName, opType, regs.R0)
}

func (code *functionCoder) exprBinaryOp(exprName, opName string, opType types.T, args []interface{}) {
	if len(args) != 2 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	code.expr(args[0], opType)
	code.opPush(opType, regs.R0)
	code.expr(args[1], opType)
	code.mach.OpMove(opType, regs.R0, regs.R1, false)
	code.opPop(opType, regs.R0)
	code.mach.BinaryOp(opName, opType, regs.R1, regs.R0)
}

func (code *functionCoder) exprConst(exprName string, opType types.T, args []interface{}) {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	code.mach.OpMoveImm(opType, args[0], regs.R0)
}

func (code *functionCoder) exprBlock(exprName string, args []interface{}, expectType types.T) (resultType types.T) {
	after := new(links.L)
	code.pushTarget(after, expectType)

	for _, arg := range args {
		resultType = code.expr(arg, types.Any)
	}

	code.popTarget()
	code.label(after)

	return
}

func (code *functionCoder) exprBr(exprName string, args []interface{}) (resultType types.T) {
	var indexes []interface{}
	var defaultIndex interface{}
	var resultExpr interface{}
	var condExpr interface{}

	switch exprName {
	case "br":
		switch len(args) {
		case 1:
			defaultIndex = args[0]

		case 2:
			defaultIndex = args[0]
			resultExpr = args[1]

		default:
			panic(fmt.Errorf("%s: wrong number of operands", exprName))
		}

	case "br_if":
		switch len(args) {
		case 2:
			defaultIndex = args[0]
			condExpr = args[1]

		case 3:
			defaultIndex = args[0]
			resultExpr = args[1]
			condExpr = args[2]

		default:
			panic(fmt.Errorf("%s: wrong number of operands", exprName))
		}

	case "br_table":
		if len(args) < 2 {
			panic(fmt.Errorf("%s: too few operands", exprName))
		}

		condExpr = args[len(args)-1]
		args = args[:len(args)-1]

		if _, ok := args[len(args)-1].([]interface{}); ok {
			resultExpr = args[len(args)-1]
			args = args[:len(args)-1]
		}

		if len(args) < 1 {
			panic(fmt.Errorf("%s: too few operands", exprName))
		}

		indexes = args[:len(args)-1]
		defaultIndex = args[len(args)-1]
	}

	defaultTarget := code.getTarget(defaultIndex)
	defaultStackDelta := code.stackOffset - defaultTarget.stackOffset

	if resultExpr != nil {
		// branch expressions don't actually return anything...
		resultType = code.expr(resultExpr, defaultTarget.expectType)
	}

	var condType types.T
	condReg := regs.R0
	condRegExt := false

	if condExpr != nil {
		if resultType != types.Void {
			code.opPush(resultType, regs.R0)
		}
		condType = code.expr(condExpr, types.AnyScalar)
		if resultType != types.Void {
			code.mach.OpMove(condType, condReg, regs.R1, true)
			condReg = regs.R1
			condRegExt = true
			code.opPop(resultType, regs.R0)
		}
	}

	switch exprName {
	case "br", "br_if":
		code.opAddToStackPtr(defaultStackDelta)

		if condExpr != nil {
			code.opBranchIf(condType, condReg, defaultTarget.label)
			code.opAddToStackPtr(-defaultStackDelta)
		} else {
			code.opBranch(defaultTarget.label)
		}

	case "br_table":
		var targets []*branchTarget

		for _, x := range indexes {
			target := code.getTarget(x)
			targets = append(targets, target)

			code.labelLinks[target.label] = struct{}{}
		}

		commonStackOffset := defaultTarget.stackOffset

		for _, target := range targets {
			if target.stackOffset != commonStackOffset {
				commonStackOffset = -1
				break
			}
		}

		var tableType types.T
		var tableScale uint8

		if commonStackOffset >= 0 {
			tableType = types.I32
			tableScale = 2
		} else {
			tableType = types.I64
			tableScale = 3
		}

		tableSize := len(targets) << tableScale
		tableAlloc, tableAddr := code.program.roData.allocate(tableSize)

		branchStackOffset := code.stackOffset

		var outOfBounds *links.L

		if commonStackOffset >= 0 {
			code.opAddToStackPtr(branchStackOffset - commonStackOffset)
			outOfBounds = defaultTarget.label
		} else if defaultStackDelta != 0 {
			outOfBounds = new(links.L) // trampoline
		} else {
			outOfBounds = defaultTarget.label
		}

		if condType != types.I32 {
			panic(condType)
		}

		code.opBranchIfOutOfBounds(condReg, len(targets), outOfBounds)

		if condRegExt {
			condType = types.I64
		}

		code.mach.OpLoadRODataRegScaleExt(tableType, tableAddr, condType, condReg, tableScale)

		var branchAddr int

		if commonStackOffset < 0 {
			// TODO: add (condReg >> 32) to regStackPtr
			// TODO: (condReg & 0xffffffff) to condReg
			panic("not implemented")
		}

		branchAddr = code.mach.OpBranchIndirect(condReg)

		tableAlloc.populator = func(data []byte) {
			for _, target := range targets {
				disp := target.label.Address - branchAddr

				if commonStackOffset >= 0 {
					machine.ByteOrder().PutUint32(data[:4], uint32(disp))
					data = data[4:]
				} else {
					delta := branchStackOffset - target.stackOffset
					packed := (uint64(uint32(delta)) << 32) | uint64(uint32(disp))
					machine.ByteOrder().PutUint64(data[:8], packed)
					data = data[8:]
				}
			}
		}

		if commonStackOffset < 0 && defaultStackDelta != 0 {
			code.label(outOfBounds) // trampoline
			code.opAddToStackPtr(defaultStackDelta)
			code.opBranch(defaultTarget.label)
		}
	}

	return
}

func (code *functionCoder) exprCall(exprName string, args []interface{}) types.T {
	if len(args) == 0 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	funcName := args[0].(string)
	target, found := code.module.NamedFunctions[funcName]
	if !found {
		panic(fmt.Errorf("%s: function not found: %s", exprName, funcName))
	}

	args = args[1:]

	argsSize := code.partialExprCallArgs(exprName, target.Signature, args)
	code.opCall(code.program.functionLinks[target])
	code.opAddToStackPtr(argsSize)

	return target.Signature.ResultType
}

func (code *functionCoder) exprCallIndirect(exprName string, args []interface{}) types.T {
	if len(args) < 2 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	var sig *Signature

	sigName := args[0].(string)
	sigNum, err := strconv.ParseUint(sigName, 10, 32)
	if err == nil {
		if sigNum < 0 || sigNum >= uint64(len(code.module.Signatures)) {
			panic(sigName)
		}
		sig = code.module.Signatures[sigNum]
	} else {
		var found bool
		if sig, found = code.module.NamedSignatures[sigName]; !found {
			panic(sigName)
		}
	}

	if sig.Index < 0 {
		panic("call_indirect to function without signature index")
	}

	indexExpr := args[1]
	args = args[2:]

	code.expr(indexExpr, types.I32)
	code.program.opTrapIfOutOfBounds(regs.R0, len(code.module.Table), &code.program.trapIndirectCallIndex)
	code.mach.OpLoadRODataRegScaleExt(types.I64, 0, types.I32, regs.R0, 3) // table is at 0
	code.opPush(types.I32, regs.R0)                                        // push func
	code.mach.OpShiftRightLogicalImm(types.I64, 32, regs.R0)               // signature id
	code.program.opTrapIfNotEqualImmTrash(types.I32, sig.Index, regs.R0, &code.program.trapIndirectCallSignature)
	argsSize := code.partialExprCallArgs(exprName, sig, args)
	code.mach.OpLoadStack(types.I32, argsSize, regs.R1, true) // load func (XXX: breaks on big endian)
	code.mach.OpCallIndirectTrash(regs.R1)
	code.opAddToStackPtr(argsSize + wordSize) // pop args + func

	return sig.ResultType
}

func (code *functionCoder) partialExprCallArgs(exprName string, sig *Signature, args []interface{}) (argsStackSize int) {
	if len(sig.ArgTypes) != len(args) {
		panic(fmt.Errorf("%s: wrong number of arguments", exprName))
	}

	for i, arg := range args {
		t := sig.ArgTypes[i]
		code.expr(arg, t)
		code.opPush(t, regs.R0)
	}

	argsStackSize = len(args) * wordSize
	return
}

func (code *functionCoder) exprGetLocal(exprName string, args []interface{}) types.T {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	varName := args[0].(string)
	offset, varType, found := code.getVarOffsetAndType(varName)
	if !found {
		panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
	}

	code.mach.OpLoadStack(varType, offset, regs.R0, false)

	return varType
}

func (code *functionCoder) exprIf(exprName string, args []interface{}) types.T {
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
	code.opBranchIfNot(t, regs.R0, afterThen)

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

		if thenType != elseType {
			panic(fmt.Errorf("%s: then and else expressions return distinct types: %s vs. %s", exprName, thenType, elseType))
		}

		code.label(afterElse)
	}

	return thenType
}

func (code *functionCoder) exprNop(exprName string, args []interface{}) (resultType types.T) {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	code.mach.OpNop()

	return
}

func (code *functionCoder) exprReturn(exprName string, args []interface{}) types.T {
	if len(args) > 1 {
		panic(fmt.Errorf("%s: too many operands", exprName))
	}

	if code.function.Signature.ResultType != types.Void && len(args) == 0 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	if len(args) > 0 {
		t := code.function.Signature.ResultType
		if t == types.Void {
			t = types.Any
		}
		code.expr(args[0], t)
	}

	code.opAddToStackPtr(code.getLocalsEndOffset())
	code.mach.OpReturn()

	return code.function.Signature.ResultType
}

func (code *functionCoder) exprUnreachable(exprName string, args []interface{}, expectType types.T) types.T {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	code.mach.OpInvalid()

	return expectType
}

func (code *functionCoder) opAddToStackPtr(offset int) {
	if offset != 0 {
		code.mach.OpAddToStackPtr(offset)
		code.stackOffset -= offset
	}
}

func (code *functionCoder) opBranch(l *links.L) {
	code.mach.StubOpBranch()
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks[l] = struct{}{}
}

func (code *functionCoder) opBranchIf(t types.T, subject regs.R, l *links.L) {
	code.mach.StubOpBranchIf(t, subject)
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks[l] = struct{}{}
}

func (code *functionCoder) opBranchIfNot(t types.T, subject regs.R, l *links.L) {
	code.mach.StubOpBranchIfNot(t, subject)
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks[l] = struct{}{}
}

func (code *functionCoder) opBranchIfOutOfBounds(indexReg regs.R, upperBound int, l *links.L) {
	code.mach.StubOpBranchIfOutOfBounds(indexReg, upperBound)
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks[l] = struct{}{}
}

func (code *functionCoder) opCall(l *links.L) {
	code.mach.StubOpCall()
	l.Sites = append(l.Sites, code.mach.Len())
}

func (code *functionCoder) opPop(t types.T, target regs.R) {
	code.mach.OpPop(t, target)
	code.stackOffset -= wordSize
}

func (code *functionCoder) opPush(t types.T, source regs.R) {
	code.mach.OpPush(t, source)
	code.stackOffset += wordSize
}

func (code *functionCoder) label(l *links.L) {
	l.Address = code.mach.Len()
}

func (code *functionCoder) pushTarget(l *links.L, expectType types.T) {
	code.targetStack = append(code.targetStack, &branchTarget{l, expectType, code.stackOffset})
}

func (code *functionCoder) popTarget() {
	code.targetStack = code.targetStack[:len(code.targetStack)-1]
}

func (code *functionCoder) getTarget(index interface{}) *branchTarget {
	i := int(values.I32(index))
	if i < 0 || i >= len(code.targetStack) {
		panic(i)
	}
	return code.targetStack[len(code.targetStack)-i-1]
}

func (code *functionCoder) getVarOffsetAndType(name string) (offset int, varType types.T, found bool) {
	v, found := code.function.Vars[name]
	if !found {
		return
	}

	if v.Param {
		paramPos := code.function.NumParams - v.Index - 1
		offset = code.getLocalsEndOffset() + machine.FunctionCallStackOverhead() + paramPos*wordSize
	} else {
		offset = code.stackOffset + v.Index*wordSize
	}

	varType = v.Type
	return
}

func (code *functionCoder) getLocalsEndOffset() int {
	return code.stackOffset + code.function.NumLocals*wordSize
}
