package wag

import (
	"errors"
	"fmt"
	"math"
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

	roTableAddr = 0
)

func (m *Module) Code() (text, roData, data []byte, bssSize int) {
	code := programCoder{
		mach:           machine.NewCoder(),
		roFloat32Addrs: make(map[uint32]int),
		roFloat64Addrs: make(map[uint64]int),
	}

	code.module(m)

	roData = code.roData.populate()

	text = code.mach.Bytes()
	return
}

type programCoder struct {
	mach           machineCoder
	roData         dataArena
	functionLinks  map[*Function]*links.L
	roFloat32Addrs map[uint32]int
	roFloat64Addrs map[uint64]int

	trapCallStackExhausted    links.L
	trapIndirectCallIndex     links.L
	trapIndirectCallSignature links.L
}

func (code *programCoder) module(m *Module) {
	code.functionLinks = make(map[*Function]*links.L)

	for _, f := range m.Functions {
		code.functionLinks[f] = new(links.L)
	}

	if len(m.Table) > 0 {
		alloc := code.roData.allocate(len(m.Table)*8, 8, func(data []byte) {
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
		})
		if alloc.addr != roTableAddr {
			panic(alloc.addr)
		}
	}

	start := m.NamedFunctions[m.Start]
	code.function(m, start)

	for _, f := range m.Functions {
		if f != start {
			code.function(m, f)
		}
	}

	code.trap(code.mach.DivideByZeroTarget(), traps.DivideByZero)
	code.trap(&code.trapCallStackExhausted, traps.CallStackExhausted)
	code.trap(&code.trapIndirectCallIndex, traps.IndirectCallIndex)
	code.trap(&code.trapIndirectCallSignature, traps.IndirectCallSignature)

	for _, link := range code.functionLinks {
		code.mach.UpdateCalls(link)
	}
}

func (program *programCoder) function(m *Module, f *Function) {
	if false {
		fmt.Println("func:", f.Names)
	}

	code := functionCoder{
		program:    program,
		module:     m,
		function:   f,
		mach:       program.mach,
		labelLinks: make(map[*links.L]struct{}),
	}

	code.mach.AlignFunction()
	program.functionLinks[f].Address = code.mach.Len()

	stackUsageAddr := code.mach.StubOpBranchIfStackExhausted()
	program.trapCallStackExhausted.Sites = append(program.trapCallStackExhausted.Sites, code.mach.Len())

	if f.NumLocals > 0 {
		code.mach.OpClear(regs.R1)

		for i := 0; i < f.NumLocals; i++ {
			code.mach.OpPush(types.I64, regs.R1)
		}
	}

	end := new(links.L)
	code.pushTarget(end, "", f.Signature.ResultType)

	var finalType types.T
	var unreachable bool

	for i, x := range f.body {
		var t types.T
		if i == len(f.body)-1 {
			t = f.Signature.ResultType
		}
		finalType, unreachable = code.expr(x, t)
	}

	if !unreachable && f.Signature.ResultType != types.Void && finalType != f.Signature.ResultType {
		panic(fmt.Errorf("last expression of function %s returns incorrect type: %s", f, finalType))
	}

	if code.popTarget() {
		unreachable = false
	}

	code.label(end)

	if code.stackOffset != 0 {
		panic(fmt.Errorf("internal: stack offset is non-zero at end of function: %d", code.stackOffset))
	}

	if len(code.targetStack) != 0 {
		panic(errors.New("internal: branch target stack is not empty at end of function"))
	}

	if unreachable {
		code.mach.OpUnreachable()
	} else {
		code.opAddToStackPtr(code.getLocalsEndOffset())
		code.mach.OpReturn()
	}

	code.mach.UpdateStackDisp(stackUsageAddr, code.getLocalsEndOffset()+code.stackUsage)

	for link := range code.labelLinks {
		code.mach.UpdateBranches(link)
	}
}

func (code *programCoder) trap(l *links.L, id traps.Id) {
	l.Address = code.mach.Len()
	code.mach.OpTrap(id)

	code.mach.UpdateBranches(l)
}

func (code *programCoder) opTrapIfOutOfBounds(indexReg regs.R, upperBound int, trap *links.L) {
	code.mach.StubOpBranchIfOutOfBounds(indexReg, upperBound)
	trap.Sites = append(trap.Sites, code.mach.Len())
}

func (code *programCoder) opTrapIfNotEqualImm32(subject regs.R, value int, trap *links.L) {
	code.mach.StubOpBranchIfNotEqualImm32(subject, value)
	trap.Sites = append(trap.Sites, code.mach.Len())
}

type branchTarget struct {
	label       *links.L
	name        string
	expectType  types.T
	stackOffset int
}

type functionCoder struct {
	module      *Module
	program     *programCoder
	function    *Function
	mach        machineCoder
	stackOffset int
	stackUsage  int
	targetStack []*branchTarget
	labelLinks  map[*links.L]struct{}
	exprDepth   int // for debugging
}

func (code *functionCoder) expr(x interface{}, expectType types.T) (resultType types.T, unreachable bool) {
	expr := x.([]interface{})
	exprName := expr[0].(string)
	args := expr[1:]

	if false {
		for i := 0; i < code.exprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<%s>\n", exprName)
	}
	code.exprDepth++

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
		case "ctz", "neg":
			code.exprUnaryOp(exprName, opName, opType, args)

		case "eq", "gt", "gt_s", "gt_u", "lt", "lt_s", "ne":
			resultType = types.I32
			fallthrough
		case "add", "and", "div", "div_u", "mul", "or", "sub", "xor":
			code.exprBinaryOp(exprName, opName, opType, args)

		case "const":
			code.exprConst(exprName, opType, args)

		default:
			panic(exprName)
		}
	} else {
		switch exprName {
		case "block":
			resultType, unreachable = code.exprBlock(exprName, args, expectType, nil)

		case "br", "br_if", "br_table":
			unreachable = code.exprBr(exprName, args)

		case "call":
			resultType = code.exprCall(exprName, args)

		case "call_indirect":
			resultType = code.exprCallIndirect(exprName, args)

		case "get_local":
			resultType = code.exprGetLocal(exprName, args)

		case "if":
			resultType, unreachable = code.exprIf(exprName, args, expectType)

		case "loop":
			resultType, unreachable = code.exprLoop(exprName, args, expectType)

		case "nop":
			code.exprNop(exprName, args)

		case "return":
			unreachable = code.exprReturn(exprName, args)

		case "set_local":
			resultType = code.exprSetLocal(exprName, args)

		case "unreachable":
			unreachable = code.exprUnreachable(exprName, args, expectType)

		default:
			panic(exprName)
		}
	}

	code.exprDepth--
	if false {
		for i := 0; i < code.exprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("</%s>\n", exprName)
	}

	if !unreachable && expectType != types.Void && resultType != expectType {
		panic(fmt.Errorf("%s: result type %s does not match expected type %s", exprName, resultType, expectType))
	}

	if unreachable {
		code.mach.OpUnreachable()
	}

	return
}

func (code *functionCoder) exprUnaryOp(exprName, opName string, opType types.T, args []interface{}) {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	code.expr(args[0], opType)
	code.mach.UnaryOp(opName, opType)
}

func (code *functionCoder) exprBinaryOp(exprName, opName string, opType types.T, args []interface{}) {
	if len(args) != 2 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	code.expr(args[0], opType)
	code.opPush(opType, regs.R0)
	code.expr(args[1], opType)
	code.mach.OpMove(opType, regs.R1, regs.R0)
	code.opPop(opType, regs.R0)
	code.mach.BinaryOp(opName, opType)
}

func (code *functionCoder) exprConst(exprName string, opType types.T, args []interface{}) {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	value := values.Parse(opType, args[0])

	switch opType.Category() {
	case types.Int:
		code.mach.OpMoveImmediateInt(opType, regs.R0, value)

	case types.Float:
		var addr int
		var found bool

		switch opType.Size() {
		case types.Size32:
			bits := math.Float32bits(value.(float32))
			addr, found = code.program.roFloat32Addrs[bits]
			if !found {
				alloc := code.program.roData.allocate(4, 4, func(data []byte) {
					machine.ByteOrder().PutUint32(data, bits)
				})
				code.program.roFloat32Addrs[bits] = alloc.addr
				addr = alloc.addr
			}

		case types.Size64:
			bits := math.Float64bits(value.(float64))
			addr, found = code.program.roFloat64Addrs[bits]
			if !found {
				alloc := code.program.roData.allocate(8, 8, func(data []byte) {
					machine.ByteOrder().PutUint64(data, bits)
				})
				code.program.roFloat64Addrs[bits] = alloc.addr
				addr = alloc.addr
			}

		default:
			panic(opType)
		}

		code.mach.OpLoadROFloatDisp(opType, regs.R0, addr)

	default:
		panic(opType)
	}
}

func (code *functionCoder) exprBlock(exprName string, args []interface{}, expectType types.T, before *links.L) (resultType types.T, unreachable bool) {
	var afterName string
	var beforeName string

	if len(args) > 0 {
		if name, ok := args[0].(string); ok {
			afterName = name
			args = args[1:]
		}

		if len(args) > 0 {
			if name, ok := args[0].(string); ok {
				beforeName = name
				args = args[1:]
			}
		}
	}

	after := new(links.L)
	code.pushTarget(after, afterName, expectType)

	if before != nil {
		code.pushTarget(before, beforeName, types.Void)
	}

	for i, arg := range args {
		var t types.T
		if i == len(args)-1 {
			t = expectType
		}

		resultType, unreachable = code.expr(arg, t)
		if unreachable {
			break
		}
	}

	if before != nil {
		code.popTarget()
	}

	if code.popTarget() {
		if unreachable {
			resultType = expectType // checked by exprBr
			unreachable = false
		}
	}

	code.label(after)

	return
}

func (code *functionCoder) exprBr(exprName string, args []interface{}) (unreachable bool) {
	var indexes []interface{}
	var defaultIndex interface{}
	var valueExpr interface{}
	var condExpr interface{}

	switch exprName {
	case "br":
		switch len(args) {
		case 1:
			defaultIndex = args[0]

		case 2:
			defaultIndex = args[0]
			valueExpr = args[1]

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
			valueExpr = args[1]
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
			valueExpr = args[len(args)-1]
			args = args[:len(args)-1]
		}

		if len(args) < 1 {
			panic(fmt.Errorf("%s: too few operands", exprName))
		}

		indexes = args[:len(args)-1]
		defaultIndex = args[len(args)-1]
	}

	defaultTarget := code.findTarget(defaultIndex)
	defaultStackDelta := code.stackOffset - defaultTarget.stackOffset

	var valueType types.T

	if valueExpr != nil {
		// branch expressions don't actually return anything...
		valueType, unreachable = code.expr(valueExpr, defaultTarget.expectType)
		if unreachable {
			return
		}
	}

	if defaultTarget.expectType != types.Void && valueType != defaultTarget.expectType {
		panic(fmt.Errorf("%s: branch value type %s differs from default branch target type %s", exprName, valueType, defaultTarget.expectType))
	}

	condReg := regs.R0

	if condExpr != nil {
		if valueType.Category() == types.Int {
			code.opPush(valueType, regs.R0)
		}

		code.expr(condExpr, types.I32)

		if valueType.Category() == types.Int {
			code.mach.OpMove(types.I32, regs.R1, regs.R0)
			condReg = regs.R1

			code.opPop(valueType, regs.R0)
		}
	}

	switch exprName {
	case "br":
		code.mach.OpAddToStackPtr(defaultStackDelta)
		code.opBranch(defaultTarget.label)

		unreachable = true

	case "br_if":
		code.mach.OpAddToStackPtr(defaultStackDelta)
		code.opBranchIf(condReg, defaultTarget.label)
		code.mach.OpAddToStackPtr(-defaultStackDelta)

	case "br_table":
		var targets []*branchTarget

		for _, x := range indexes {
			target := code.findTarget(x)
			targets = append(targets, target)

			if target.expectType != types.Void && valueType != target.expectType {
				panic(fmt.Errorf("%s: branch value type %s differs from non-default branch target type %s", exprName, valueType, target.expectType))
			}

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
		tableAlloc := code.program.roData.allocate(tableSize, 1<<tableScale, nil)

		branchStackOffset := code.stackOffset

		var outOfBounds *links.L

		if commonStackOffset >= 0 {
			code.mach.OpAddToStackPtr(branchStackOffset - commonStackOffset)
			outOfBounds = defaultTarget.label
		} else if defaultStackDelta != 0 {
			outOfBounds = new(links.L) // trampoline
		} else {
			outOfBounds = defaultTarget.label
		}

		code.opBranchIfOutOfBounds(condReg, len(targets), outOfBounds)
		code.mach.OpLoadROIntIndex32ScaleDisp(tableType, condReg, tableScale, tableAlloc.addr, true)

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
			code.mach.OpAddToStackPtr(defaultStackDelta)
			code.opBranch(defaultTarget.label)
		}
	}

	return
}

func (code *functionCoder) exprCall(exprName string, args []interface{}) types.T {
	if len(args) == 0 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	var target *Function

	funcName := args[0].(string)
	funcNum, err := strconv.ParseUint(funcName, 10, 32)
	if err == nil {
		if funcNum < 0 || funcNum >= uint64(len(code.module.Functions)) {
			panic(funcName)
		}
		target = code.module.Functions[funcNum]
	} else {
		var found bool
		target, found = code.module.NamedFunctions[funcName]
		if !found {
			panic(fmt.Errorf("%s: function not found: %s", exprName, funcName))
		}
	}

	argsSize := code.partialExprCallArgs(exprName, target.Signature, args[1:])
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
	code.mach.OpLoadROIntIndex32ScaleDisp(types.I64, regs.R0, 3, roTableAddr, false)
	code.opPush(types.I32, regs.R0)              // push func
	code.mach.OpShiftRightLogical32Bits(regs.R0) // signature id
	code.program.opTrapIfNotEqualImm32(regs.R0, sig.Index, &code.program.trapIndirectCallSignature)
	argsSize := code.partialExprCallArgs(exprName, sig, args)
	code.mach.OpCallIndirectDisp32FromStack(argsSize)
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

	if n := code.stackOffset + machine.FunctionCallStackOverhead(); n > code.stackUsage {
		code.stackUsage = n
	}

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

	code.mach.OpLoadStack(varType, regs.R0, offset)

	return varType
}

func (code *functionCoder) exprs(x interface{}, name string, after *links.L, expectType types.T) (resultType types.T, unreachable, afterReached bool) {
	args := x.([]interface{})

	var afterName string

	if len(args) > 0 {
		if s, ok := args[0].(string); ok && s == name {
			args = args[1:]

			if len(args) > 0 {
				if s, ok := args[0].(string); ok {
					afterName = s
					args = args[1:]
				}
			}
		}
	}

	code.pushTarget(after, afterName, expectType)

	if len(args) > 0 {
		switch args[0].(type) {
		case string:
			resultType, unreachable = code.expr(args, expectType)

		case []interface{}:
			for i, expr := range args {
				var t types.T
				if i == len(args)-1 {
					t = expectType
				}

				resultType, unreachable = code.expr(expr, t)
				if unreachable {
					break
				}
			}
		}
	}

	afterReached = code.popTarget()

	return
}

func (code *functionCoder) exprIf(exprName string, args []interface{}, expectType types.T) (resultType types.T, unreachable bool) {
	if len(args) < 2 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	haveElse := len(args) == 3

	if len(args) > 3 {
		panic(fmt.Errorf("%s: too many operands", exprName))
	}

	end := new(links.L)
	afterThen := new(links.L)

	code.expr(args[0], types.I32)
	code.opBranchIfNot(regs.R0, afterThen)

	resultType, thenDeadend, endReachable := code.exprs(args[1], "then", end, expectType)

	if haveElse {
		if thenDeadend {
			code.mach.OpUnreachable()
		} else {
			code.opBranch(end)
			endReachable = true
		}
		code.label(afterThen)

		altResultType, elseDeadend, altEndReachable := code.exprs(args[2], "else", end, expectType)

		if altEndReachable {
			endReachable = true
		}

		if elseDeadend {
			code.mach.OpUnreachable()
		} else {
			if resultType != altResultType {
				if thenDeadend {
					resultType = altResultType
				} else {
					panic(fmt.Errorf("%s: then and else expressions return distinct types: %s vs. %s", exprName, resultType, altResultType))
				}
			}
			endReachable = true
		}
	} else {
		endReachable = true
		code.label(afterThen)
	}

	code.label(end)

	unreachable = !endReachable
	return
}

func (code *functionCoder) exprLoop(exprName string, args []interface{}, expectType types.T) (resultType types.T, unreachable bool) {
	before := new(links.L)
	code.label(before)

	return code.exprBlock(exprName, args, expectType, before)
}

func (code *functionCoder) exprNop(exprName string, args []interface{}) {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}
}

func (code *functionCoder) exprReturn(exprName string, args []interface{}) (unreachable bool) {
	if len(args) > 1 {
		panic(fmt.Errorf("%s: too many operands", exprName))
	}

	if code.function.Signature.ResultType != types.Void && len(args) == 0 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	if len(args) > 0 {
		code.expr(args[0], code.function.Signature.ResultType)
	}

	code.mach.OpAddToStackPtr(code.getLocalsEndOffset())
	code.mach.OpReturn()

	unreachable = true
	return
}

func (code *functionCoder) exprSetLocal(exprName string, args []interface{}) types.T {
	if len(args) != 2 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	varName := args[0].(string)
	offset, varType, found := code.getVarOffsetAndType(varName)
	if !found {
		panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
	}

	code.expr(args[1], varType)
	code.mach.OpStoreStack(varType, offset, regs.R0)

	return varType // this contradicts the design doc, but needed for labels.wast
}

func (code *functionCoder) exprUnreachable(exprName string, args []interface{}, expectType types.T) bool {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	code.mach.OpUnreachable()

	return true
}

func (code *functionCoder) opAddToStackPtr(offset int) {
	code.mach.OpAddToStackPtr(offset)
	code.stackOffset -= offset
}

func (code *functionCoder) opBranch(l *links.L) {
	code.mach.StubOpBranch()
	code.branchSite(l)
}

func (code *functionCoder) opBranchIf(subject regs.R, l *links.L) {
	code.mach.StubOpBranchIf(subject)
	code.branchSite(l)
}

func (code *functionCoder) opBranchIfNot(subject regs.R, l *links.L) {
	code.mach.StubOpBranchIfNot(subject)
	code.branchSite(l)
}

func (code *functionCoder) opBranchIfOutOfBounds(indexReg regs.R, upperBound int, l *links.L) {
	code.mach.StubOpBranchIfOutOfBounds(indexReg, upperBound)
	code.branchSite(l)
}

func (code *functionCoder) opCall(l *links.L) {
	code.mach.StubOpCall()
	code.callSite(l)
}

func (code *functionCoder) opPop(t types.T, target regs.R) {
	code.mach.OpPop(t, target)
	code.stackOffset -= wordSize
}

func (code *functionCoder) opPush(t types.T, source regs.R) {
	code.mach.OpPush(t, source)
	code.stackOffset += wordSize
	if code.stackOffset > code.stackUsage {
		code.stackUsage = code.stackOffset
	}
}

func (code *functionCoder) label(l *links.L) {
	l.Address = code.mach.Len()
}

func (code *functionCoder) branchSite(l *links.L) {
	l.Sites = append(l.Sites, code.mach.Len())
	code.labelLinks[l] = struct{}{}
}

func (code *functionCoder) callSite(l *links.L) {
	l.Sites = append(l.Sites, code.mach.Len())
}

func (code *functionCoder) pushTarget(l *links.L, name string, expectType types.T) {
	code.targetStack = append(code.targetStack, &branchTarget{l, name, expectType, code.stackOffset})
}

func (code *functionCoder) popTarget() (live bool) {
	target := code.targetStack[len(code.targetStack)-1]
	_, live = code.labelLinks[target.label]

	code.targetStack = code.targetStack[:len(code.targetStack)-1]
	return
}

func (code *functionCoder) findTarget(token interface{}) *branchTarget {
	name := token.(string)

	for i := len(code.targetStack) - 1; i >= 0; i-- {
		target := code.targetStack[i]
		if target.name != "" && target.name == name {
			return target
		}
	}

	i := int(values.I32(token))
	if i >= 0 && i < len(code.targetStack) {
		return code.targetStack[len(code.targetStack)-i-1]
	}

	panic(name)
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
