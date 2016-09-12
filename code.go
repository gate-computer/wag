package wag

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
)

const (
	roTableAddr = 0
)

func (m *Module) Code() (text, roData, data []byte, bssSize int) {
	var code gen.Coder

	prog := programCoder{
		roFloat32Addrs: make(map[uint32]int),
		roFloat64Addrs: make(map[uint64]int),
	}

	prog.module(&code, m)

	roData = prog.roData.populate()

	text = code.Bytes()
	return
}

type programCoder struct {
	roData         dataArena
	functionLinks  map[*Function]*links.L
	roFloat32Addrs map[uint32]int
	roFloat64Addrs map[uint64]int
}

func (prog *programCoder) module(code *gen.Coder, m *Module) {
	prog.functionLinks = make(map[*Function]*links.L)

	for _, f := range m.Functions {
		prog.functionLinks[f] = new(links.L)
	}

	if len(m.Table) > 0 {
		alloc := prog.roData.allocate(len(m.Table)*8, 8, func(data []byte) {
			for _, f := range m.Table {
				if f.Signature.Index < 0 {
					panic("function signature has no index while populating table")
				}

				addr := uint32(prog.functionLinks[f].Address)
				sigId := uint32(f.Signature.Index)
				packed := (uint64(sigId) << 32) | uint64(addr)
				mach.ByteOrder().PutUint64(data[:8], packed)
				data = data[8:]
			}
		})
		if alloc.addr != roTableAddr {
			panic(alloc.addr)
		}
	}

	start := m.NamedFunctions[m.Start]
	prog.function(code, m, start)

	for _, f := range m.Functions {
		if f != start {
			prog.function(code, m, f)
		}
	}

	prog.trap(code, &code.TrapDivideByZero, traps.DivideByZero)
	prog.trap(code, &code.TrapCallStackExhausted, traps.CallStackExhausted)
	prog.trap(code, &code.TrapIndirectCallIndex, traps.IndirectCallIndex)
	prog.trap(code, &code.TrapIndirectCallSignature, traps.IndirectCallSignature)
	prog.trap(code, &code.TrapUnreachable, traps.Unreachable)

	for _, link := range prog.functionLinks {
		mach.UpdateCalls(code, link)
	}
}

func (prog *programCoder) function(code *gen.Coder, m *Module, f *Function) {
	if false {
		fmt.Println("func:", f.Names)
	}

	proc := functionCoder{
		prog:       prog,
		module:     m,
		function:   f,
		labelLinks: make(map[*links.L]struct{}),
	}

	mach.AlignFunction(code)
	functionAddr := code.Len()
	stackUsageAddr := mach.StubOpBranchIfStackExhausted(code)
	stackCheckAddr := code.Len()

	if f.NumLocals > 0 {
		mach.OpClear(code, regs.R1)
		zero := values.RegOperand(regs.R1)

		for i := 0; i < f.NumLocals; i++ {
			mach.OpPush(code, types.I64, zero)
		}
	}

	end := new(links.L)
	proc.pushTarget(end, "", f.Signature.ResultType)

	var result values.Operand
	var deadend bool

	for i, x := range f.body {
		var t types.T
		if i == len(f.body)-1 {
			t = f.Signature.ResultType
		}

		result, deadend = proc.expr(code, x, t)
		if deadend {
			mach.OpAbort(code)
			break
		}
	}

	if !deadend {
		proc.opMove(code, f.Signature.ResultType, regs.R0, result)
	}

	if proc.popTarget() {
		deadend = false
	}

	proc.label(code, end)

	if proc.stackOffset != 0 {
		panic(fmt.Errorf("internal: stack offset is non-zero at end of function: %d", proc.stackOffset))
	}

	if len(proc.targetStack) != 0 {
		panic(errors.New("internal: branch target stack is not empty at end of function"))
	}

	totalStackUsage := proc.function.NumLocals*mach.WordSize() + proc.stackUsage

	if !deadend {
		mach.OpAddImmToStackPtr(code, proc.function.NumLocals*mach.WordSize())
		mach.OpReturn(code)
	}

	for link := range proc.labelLinks {
		mach.UpdateBranches(code, link)
	}

	if totalStackUsage > 0 {
		mach.UpdateStackDisp(code, stackUsageAddr, totalStackUsage)
		code.TrapCallStackExhausted.AddSite(stackCheckAddr)
	} else {
		newAddr := stackCheckAddr &^ (mach.FunctionAlignment() - 1)
		if functionAddr == 0 {
			// start function
			mach.DisableCode(code, functionAddr, newAddr)
		} else {
			mach.DeleteCode(code, functionAddr, newAddr)
		}
		mach.DisableCode(code, newAddr, stackCheckAddr)
		functionAddr = newAddr
	}

	prog.functionLinks[f].Address = functionAddr
}

func (prog *programCoder) trap(code *gen.Coder, l *links.L, id traps.Id) {
	l.Address = code.Len()
	mach.OpTrap(code, id)

	mach.UpdateBranches(code, l)
}

func (prog *programCoder) trapSite(code *gen.Coder, l *links.L) {
	l.AddSite(code.Len())
}

func (prog *programCoder) opTrap(code *gen.Coder, trap *links.L) {
	mach.StubOpBranch(code)
	prog.trapSite(code, trap)
}

func (prog *programCoder) opTrapIfOutOfBounds(code *gen.Coder, indexReg regs.R, upperBound int, trap *links.L) {
	mach.StubOpBranchIfOutOfBounds(code, indexReg, upperBound)
	prog.trapSite(code, trap)
}

func (prog *programCoder) opTrapIfNotEqualImm32(code *gen.Coder, x values.Operand, value int, trap *links.L) {
	mach.StubOpBranchIfNotEqualImm32(code, x, value)
	prog.trapSite(code, trap)
}

type liveOperand struct {
	typ types.T
	ref *values.Operand
}

type branchTarget struct {
	label       *links.L
	name        string
	expectType  types.T
	stackOffset int
}

type functionCoder struct {
	module       *Module
	prog         *programCoder
	function     *Function
	liveOperands []liveOperand
	stackOffset  int
	stackUsage   int
	targetStack  []*branchTarget
	labelLinks   map[*links.L]struct{}
	exprDepth    int // for debugging
}

func (proc *functionCoder) expr(code *gen.Coder, x interface{}, expectType types.T) (result values.Operand, deadend bool) {
	expr := x.([]interface{})
	exprName := expr[0].(string)
	args := expr[1:]

	var resultType types.T

	if false {
		for i := 0; i < proc.exprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<%s>\n", exprName)
	}
	proc.exprDepth++

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
			result, deadend = proc.exprUnaryOp(code, exprName, opName, opType, args)

		case "eq", "gt", "gt_s", "gt_u", "lt", "lt_s", "ne":
			resultType = types.I32
			fallthrough
		case "add", "and", "div", "div_u", "mul", "or", "sub", "xor":
			result, deadend = proc.exprBinaryOp(code, exprName, opName, opType, args)

		case "const":
			result = proc.exprConst(code, exprName, opType, args)

		default:
			panic(exprName)
		}
	} else {
		switch exprName {
		case "block":
			result, deadend = proc.exprBlock(code, exprName, args, expectType, nil)
			resultType = expectType

		case "br", "br_if", "br_table":
			deadend = proc.exprBr(code, exprName, args)

		case "call":
			result, resultType, deadend = proc.exprCall(code, exprName, args)

		case "call_indirect":
			result, resultType, deadend = proc.exprCallIndirect(code, exprName, args)

		case "get_local":
			result, resultType = proc.exprGetLocal(code, exprName, args)

		case "if":
			result, deadend = proc.exprIf(code, exprName, args, expectType)
			resultType = expectType

		case "loop":
			result, deadend = proc.exprLoop(code, exprName, args, expectType)
			resultType = expectType

		case "nop":
			proc.exprNop(code, exprName, args)

		case "return":
			proc.exprReturn(code, exprName, args)
			deadend = true

		case "set_local":
			result, resultType, deadend = proc.exprSetLocal(code, exprName, args)

		case "unreachable":
			proc.exprUnreachable(code, exprName, args)
			deadend = true

		default:
			panic(exprName)
		}
	}

	proc.exprDepth--
	if false {
		for i := 0; i < proc.exprDepth+1; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("%s %s\n", resultType, result)

		for i := 0; i < proc.exprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("</%s>\n", exprName)
	}

	if deadend {
		mach.OpAbort(code)
		result = values.NoOperand
	} else {
		if expectType != types.Void && resultType != expectType {
			panic(fmt.Errorf("%s: result type %s does not match expected type %s", exprName, resultType, expectType))
		}

		if resultType != types.Void && result.Storage == values.Nowhere {
			panic(fmt.Errorf("%s: result type is %s but result operand is %s", exprName, resultType, result))
		}
	}

	if result.Storage == values.StackPop {
		// TODO: allow this and move it to register here?
		panic(fmt.Errorf("%s: result operand is %s", exprName, result))
	}

	return
}

func (proc *functionCoder) exprUnaryOp(code *gen.Coder, exprName, opName string, opType types.T, args []interface{}) (result values.Operand, deadend bool) {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	proc.saveLiveRegOperands(code, opType, 1)

	x, deadend := proc.expr(code, args[0], opType)
	if deadend {
		mach.OpAbort(code)
		return
	}

	result = proc.unaryOp(code, opName, opType, x)
	return
}

func (proc *functionCoder) exprBinaryOp(code *gen.Coder, exprName, opName string, opType types.T, args []interface{}) (result values.Operand, deadend bool) {
	if len(args) != 2 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	proc.saveLiveRegOperands(code, opType, 3)

	left, deadend := proc.expr(code, args[0], opType)
	if deadend {
		mach.OpAbort(code)
		return
	}

	proc.pushLiveOperand(opType, &left)
	right, deadend := proc.expr(code, args[1], opType)
	proc.popLiveOperand()
	if deadend {
		proc.access(left) // live operand may have been pushed to stack
		mach.OpAbort(code)
		return
	}

	result = proc.binaryOp(code, opName, opType, left, right)
	return
}

func (proc *functionCoder) exprConst(code *gen.Coder, exprName string, opType types.T, args []interface{}) values.Operand {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	imm := values.ParseImm(opType, args[0])

	switch opType {
	case types.F32:
		bits := imm.Imm(opType).(uint32)
		addr, found := proc.prog.roFloat32Addrs[bits]
		if !found {
			alloc := proc.prog.roData.allocate(4, 4, func(data []byte) {
				mach.ByteOrder().PutUint32(data, bits)
			})
			proc.prog.roFloat32Addrs[bits] = alloc.addr
			addr = alloc.addr
		}

		return values.RODataOperand(addr)

	case types.F64:
		bits := imm.Imm(opType).(uint64)
		addr, found := proc.prog.roFloat64Addrs[bits]
		if !found {
			alloc := proc.prog.roData.allocate(8, 8, func(data []byte) {
				mach.ByteOrder().PutUint64(data, bits)
			})
			proc.prog.roFloat64Addrs[bits] = alloc.addr
			addr = alloc.addr
		}

		return values.RODataOperand(addr)

	default:
		return imm
	}
}

func (proc *functionCoder) exprBlock(code *gen.Coder, exprName string, args []interface{}, expectType types.T, before *links.L) (result values.Operand, deadend bool) {
	proc.saveAllLiveOperands(code)

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
	proc.pushTarget(after, afterName, expectType)

	if before != nil {
		proc.pushTarget(before, beforeName, types.Void)
	}

	for i, arg := range args {
		var t types.T
		if i == len(args)-1 {
			t = expectType
		}

		result, deadend = proc.expr(code, arg, t)
		if deadend {
			mach.OpAbort(code)
			break
		}

		if i < len(args)-1 {
			proc.discard(code, result)
		}
	}

	if before != nil {
		proc.popTarget()
	}

	if proc.popTarget() {
		if deadend {
			deadend = false
		} else {
			proc.opMove(code, expectType, regs.R0, result)
		}

		if expectType != types.Void {
			result = values.RegOperand(regs.R0)
		}
	}

	if deadend {
		mach.OpAbort(code)
	}

	proc.label(code, after)

	return
}

func (proc *functionCoder) exprBr(code *gen.Coder, exprName string, args []interface{}) (deadend bool) {
	proc.saveAllLiveOperands(code)

	var tableIndexes []interface{}
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

		tableIndexes = args[:len(args)-1]
		defaultIndex = args[len(args)-1]

		if len(tableIndexes) == 0 {
			exprName = "br"
		}
	}

	defaultTarget := proc.findTarget(defaultIndex)
	defaultStackDelta := proc.stackOffset - defaultTarget.stackOffset

	valueType := defaultTarget.expectType

	var tableTargets []*branchTarget

	for _, x := range tableIndexes {
		target := proc.findTarget(x)

		if target.expectType != types.Void {
			switch {
			case valueType == types.Void:
				valueType = target.expectType

			case valueType != target.expectType:
				panic(fmt.Errorf("%s: branch targets have inconsistent types: %s vs. %s", exprName, valueType, target.expectType))
			}
		}

		tableTargets = append(tableTargets, target)

		proc.labelLinks[target.label] = struct{}{}
	}

	var valueOperand values.Operand

	if valueExpr != nil {
		valueOperand, deadend = proc.expr(code, valueExpr, valueType)
		if deadend {
			mach.OpAbort(code)
			return
		}
	}

	var condOperand values.Operand

	if condExpr != nil {
		proc.pushLiveOperand(valueType, &valueOperand)
		condOperand, deadend = proc.expr(code, condExpr, types.I32)
		proc.popLiveOperand()
		if deadend {
			proc.access(valueOperand) // live operand may have been pushed to stack
			mach.OpAbort(code)
			return
		}

		if reg, ok := condOperand.CheckReg(); ok && reg == regs.R0 {
			condOperand = proc.opMove(code, types.I32, regs.R1, condOperand)
		}
	}

	proc.opMove(code, valueType, regs.R0, valueOperand)

	switch exprName {
	case "br":
		mach.OpAddImmToStackPtr(code, defaultStackDelta)
		proc.opBranch(code, defaultTarget.label)

		deadend = true

	case "br_if":
		mach.OpAddImmToStackPtr(code, defaultStackDelta)
		proc.opBranchIf(code, condOperand, defaultTarget.label)
		mach.OpAddImmToStackPtr(code, -defaultStackDelta)

	case "br_table":
		commonStackOffset := tableTargets[0].stackOffset

		for _, target := range tableTargets[1:] {
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

		tableSize := len(tableTargets) << tableScale
		tableAlloc := proc.prog.roData.allocate(tableSize, 1<<tableScale, nil)

		operand := condOperand
		reg, ok := operand.CheckReg()
		if !ok {
			reg = regs.R1
			operand = proc.opMove(code, types.I32, reg, operand)
		}

		mach.OpAddImmToStackPtr(code, defaultStackDelta)
		tableStackOffset := proc.stackOffset - defaultStackDelta

		proc.opBranchIfOutOfBounds(code, reg, len(tableTargets), defaultTarget.label)
		mach.OpLoadROIntIndex32ScaleDisp(code, tableType, reg, tableScale, tableAlloc.addr, true)
		addrType := types.I64 // loaded with zero-extend

		if commonStackOffset >= 0 {
			mach.OpAddImmToStackPtr(code, tableStackOffset-commonStackOffset)
		} else {
			proc.opMove(code, types.I64, regs.R2, operand)
			mach.OpShiftRightLogical32Bits(code, regs.R2)
			mach.OpAddToStackPtr(code, regs.R2)
			addrType = types.I32 // upper half of register still contains stack offset
		}

		branchAddr := mach.OpBranchIndirect(code, addrType, reg)

		tableAlloc.populator = func(data []byte) {
			for _, target := range tableTargets {
				disp := target.label.Address - branchAddr

				if commonStackOffset >= 0 {
					mach.ByteOrder().PutUint32(data[:4], uint32(disp))
					data = data[4:]
				} else {
					delta := tableStackOffset - target.stackOffset
					packed := (uint64(uint32(delta)) << 32) | uint64(uint32(disp))
					mach.ByteOrder().PutUint64(data[:8], packed)
					data = data[8:]
				}
			}
		}
	}

	return
}

func (proc *functionCoder) exprCall(code *gen.Coder, exprName string, args []interface{}) (result values.Operand, resultType types.T, deadend bool) {
	if len(args) == 0 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	proc.saveAllLiveOperands(code)

	var target *Function

	funcName := args[0].(string)
	funcNum, err := strconv.ParseUint(funcName, 10, 32)
	if err == nil {
		if funcNum < 0 || funcNum >= uint64(len(proc.module.Functions)) {
			panic(funcName)
		}
		target = proc.module.Functions[funcNum]
	} else {
		var found bool
		target, found = proc.module.NamedFunctions[funcName]
		if !found {
			panic(fmt.Errorf("%s: function not found: %s", exprName, funcName))
		}
	}

	result, resultType, deadend, argsSize := proc.partialCallArgsExpr(code, exprName, target.Signature, args[1:])
	if deadend {
		mach.OpAbort(code)
		return
	}

	proc.opCall(code, proc.prog.functionLinks[target])
	proc.opAddImmToStackPtr(code, argsSize)

	return
}

func (proc *functionCoder) exprCallIndirect(code *gen.Coder, exprName string, args []interface{}) (result values.Operand, resultType types.T, deadend bool) {
	if len(args) < 2 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	proc.saveAllLiveOperands(code)

	var sig *Signature

	sigName := args[0].(string)
	sigNum, err := strconv.ParseUint(sigName, 10, 32)
	if err == nil {
		if sigNum < 0 || sigNum >= uint64(len(proc.module.Signatures)) {
			panic(sigName)
		}
		sig = proc.module.Signatures[sigNum]
	} else {
		var found bool
		if sig, found = proc.module.NamedSignatures[sigName]; !found {
			panic(sigName)
		}
	}

	if sig.Index < 0 {
		panic("call_indirect to function without signature index")
	}

	indexExpr := args[1]
	args = args[2:]

	operand, deadend := proc.expr(code, indexExpr, types.I32)
	if deadend {
		mach.OpAbort(code)
		return
	}

	reg, ok := operand.CheckReg()
	if !ok {
		reg = regs.R0
		operand = proc.opMove(code, types.I32, reg, operand)
	}

	proc.prog.opTrapIfOutOfBounds(code, reg, len(proc.module.Table), &code.TrapIndirectCallIndex)
	mach.OpLoadROIntIndex32ScaleDisp(code, types.I64, reg, 3, roTableAddr, false)
	proc.opPush(code, types.I32, operand)     // push func
	mach.OpShiftRightLogical32Bits(code, reg) // signature id
	proc.prog.opTrapIfNotEqualImm32(code, operand, sig.Index, &code.TrapIndirectCallSignature)

	result, resultType, deadend, argsSize := proc.partialCallArgsExpr(code, exprName, sig, args)
	if deadend {
		mach.OpAbort(code)
		return
	}

	mach.OpCallIndirectDisp32FromStack(code, argsSize)
	proc.opAddImmToStackPtr(code, argsSize+mach.WordSize()) // pop args + func

	return
}

func (proc *functionCoder) partialCallArgsExpr(code *gen.Coder, exprName string, sig *Signature, args []interface{}) (result values.Operand, resultType types.T, deadend bool, argsStackSize int) {
	if len(sig.ArgTypes) != len(args) {
		panic(fmt.Errorf("%s: wrong number of arguments", exprName))
	}

	for i, arg := range args {
		t := sig.ArgTypes[i]

		var x values.Operand
		x, deadend = proc.expr(code, arg, t)
		if deadend {
			mach.OpAbort(code)
			break
		}

		proc.opPush(code, t, x)
		argsStackSize += mach.WordSize()
	}

	if n := proc.stackOffset + mach.FunctionCallStackOverhead(); n > proc.stackUsage {
		proc.stackUsage = n
	}

	if deadend {
		proc.stackOffset -= argsStackSize // revert pushes
		return
	}

	resultType = sig.ResultType

	if resultType != types.Void {
		result = values.RegOperand(regs.R0)
	}

	return
}

func (proc *functionCoder) exprGetLocal(code *gen.Coder, exprName string, args []interface{}) (result values.Operand, resultType types.T) {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	varName := args[0].(string)
	offset, resultType, found := proc.getVarOffsetAndType(varName)
	if !found {
		panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
	}

	result = values.StackOffsetOperand(offset)
	return
}

func (proc *functionCoder) exprs(code *gen.Coder, x interface{}, name string, end *links.L, expectType types.T) (deadend, endReached bool) {
	args := x.([]interface{})

	var endName string

	if len(args) > 0 {
		if s, ok := args[0].(string); ok && s == name {
			args = args[1:]

			if len(args) > 0 {
				if s, ok := args[0].(string); ok {
					endName = s
					args = args[1:]
				}
			}
		}
	}

	proc.pushTarget(end, endName, expectType)

	var result values.Operand

	if len(args) > 0 {
		switch args[0].(type) {
		case string:
			result, deadend = proc.expr(code, args, expectType)

		case []interface{}:
			for i, expr := range args {
				var t types.T
				if i == len(args)-1 {
					t = expectType
				}

				result, deadend = proc.expr(code, expr, t)
				if deadend {
					break
				}

				if i < len(args)-1 {
					proc.discard(code, result)
				}
			}
		}
	}

	if deadend {
		mach.OpAbort(code)
	} else {
		proc.opMove(code, expectType, regs.R0, result)
	}

	endReached = proc.popTarget()

	return
}

func (proc *functionCoder) exprIf(code *gen.Coder, exprName string, args []interface{}, expectType types.T) (result values.Operand, deadend bool) {
	if len(args) < 2 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	proc.saveAllLiveOperands(code)

	haveElse := len(args) == 3

	if len(args) > 3 {
		panic(fmt.Errorf("%s: too many operands", exprName))
	}

	end := new(links.L)
	afterThen := new(links.L)

	ifResult, deadend := proc.expr(code, args[0], types.I32)
	if deadend {
		return
	}

	proc.opBranchIfNot(code, ifResult, afterThen)

	thenDeadend, endReachable := proc.exprs(code, args[1], "then", end, expectType)

	if haveElse {
		if !thenDeadend {
			proc.opBranch(code, end)
			endReachable = true
		}
		proc.label(code, afterThen)

		elseDeadend, endReachableFromElse := proc.exprs(code, args[2], "else", end, expectType)

		if !elseDeadend {
			endReachable = true
		}
		if endReachableFromElse {
			endReachable = true
		}
	} else {
		endReachable = true
		proc.label(code, afterThen)
	}

	proc.label(code, end)

	if expectType != types.Void {
		result = values.RegOperand(regs.R0)
	}

	deadend = !endReachable
	return
}

func (proc *functionCoder) exprLoop(code *gen.Coder, exprName string, args []interface{}, expectType types.T) (result values.Operand, deadend bool) {
	before := new(links.L)
	proc.label(code, before)

	return proc.exprBlock(code, exprName, args, expectType, before)
}

func (proc *functionCoder) exprNop(code *gen.Coder, exprName string, args []interface{}) {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}
}

func (proc *functionCoder) exprReturn(code *gen.Coder, exprName string, args []interface{}) {
	if len(args) > 1 {
		panic(fmt.Errorf("%s: too many operands", exprName))
	}

	t := proc.function.Signature.ResultType

	if t != types.Void && len(args) == 0 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	if len(args) > 0 {
		x, deadend := proc.expr(code, args[0], t)
		if deadend {
			mach.OpAbort(code)
			return
		}

		proc.opMove(code, t, regs.R0, x)
	}

	mach.OpAddImmToStackPtr(code, proc.stackOffset+proc.function.NumLocals*mach.WordSize())
	mach.OpReturn(code)
}

func (proc *functionCoder) exprSetLocal(code *gen.Coder, exprName string, args []interface{}) (result values.Operand, resultType types.T, deadend bool) {
	if len(args) != 2 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	varName := args[0].(string)
	offset, resultType, found := proc.getVarOffsetAndType(varName)
	if !found {
		panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
	}

	proc.saveLiveStackOffsetOperand(code, offset)
	proc.saveLiveRegOperand(code, resultType, regs.R0) // see below

	result, deadend = proc.expr(code, args[1], resultType)
	if deadend {
		mach.OpAbort(code)
		return
	}

	// The design doc says that set_local does't return a value, but it's
	// needed for the labels.wast test to work.  Make sure it can be accessed
	// twice.
	if result.Once() {
		result = proc.opMove(code, resultType, regs.R0, result)
	}

	proc.opStoreStack(code, resultType, offset, result)
	return
}

func (proc *functionCoder) exprUnreachable(code *gen.Coder, exprName string, args []interface{}) {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	proc.prog.opTrap(code, &code.TrapUnreachable)
}

func (proc *functionCoder) access(o values.Operand) values.Operand {
	switch o.Storage {
	case values.StackOffset:
		o = values.StackOffsetOperand(proc.stackOffset + o.Offset())

	case values.StackPop:
		proc.stackOffset -= mach.WordSize()
	}

	return o
}

func (proc *functionCoder) discard(code *gen.Coder, o values.Operand) {
	if o.Storage == values.StackPop {
		proc.opAddImmToStackPtr(code, 8)
	}
}

func (proc *functionCoder) unaryOp(code *gen.Coder, name string, t types.T, x values.Operand) values.Operand {
	x = proc.access(x)
	return mach.UnaryOp(code, name, t, x)
}

func (proc *functionCoder) binaryOp(code *gen.Coder, name string, t types.T, a, b values.Operand) values.Operand {
	a = proc.access(a)
	b = proc.access(b)
	return mach.BinaryOp(code, name, t, a, b)
}

func (proc *functionCoder) opAddImmToStackPtr(code *gen.Coder, offset int) {
	proc.stackOffset -= offset
	mach.OpAddImmToStackPtr(code, offset)
}

func (proc *functionCoder) opBranch(code *gen.Coder, l *links.L) {
	mach.StubOpBranch(code)
	proc.branchSite(code, l)
}

func (proc *functionCoder) opBranchIf(code *gen.Coder, x values.Operand, l *links.L) {
	x = proc.access(x)
	mach.StubOpBranchIf(code, x)
	proc.branchSite(code, l)
}

func (proc *functionCoder) opBranchIfNot(code *gen.Coder, x values.Operand, l *links.L) {
	x = proc.access(x)
	mach.StubOpBranchIfNot(code, x)
	proc.branchSite(code, l)
}

func (proc *functionCoder) opBranchIfOutOfBounds(code *gen.Coder, indexReg regs.R, upperBound int, l *links.L) {
	mach.StubOpBranchIfOutOfBounds(code, indexReg, upperBound)
	proc.branchSite(code, l)
}

func (proc *functionCoder) opCall(code *gen.Coder, l *links.L) {
	mach.StubOpCall(code)
	proc.callSite(code, l)
}

func (proc *functionCoder) opMove(code *gen.Coder, t types.T, target regs.R, x values.Operand) values.Operand {
	if t == types.Void {
		proc.discard(code, x)
		return values.NoOperand
	}

	proc.saveLiveRegOperand(code, t, target)

	x = proc.access(x)

	if reg, ok := x.CheckReg(); !(ok && reg == target) {
		mach.OpMove(code, t, target, x)
	}

	return values.RegOperand(target)
}

func (proc *functionCoder) opPush(code *gen.Coder, t types.T, x values.Operand) values.Operand {
	if x.Storage == values.StackPop {
		panic(x) // XXX: ?
	}

	proc.saveAllLiveOperands(code)

	x = proc.access(x)
	mach.OpPush(code, t, x)

	proc.stackOffset += mach.WordSize()

	if proc.stackOffset > proc.stackUsage {
		proc.stackUsage = proc.stackOffset
	}

	return values.StackPopOperand
}

func (proc *functionCoder) opStoreStack(code *gen.Coder, t types.T, offset int, x values.Operand) {
	x = proc.access(x)
	mach.OpStoreStack(code, t, proc.stackOffset+offset, x)
}

func (proc *functionCoder) pushLiveOperand(t types.T, ref *values.Operand) {
	proc.liveOperands = append(proc.liveOperands, liveOperand{t, ref})
}

func (proc *functionCoder) popLiveOperand() {
	proc.liveOperands = proc.liveOperands[:len(proc.liveOperands)-1]
}

func (proc *functionCoder) saveLiveRegOperand(code *gen.Coder, t types.T, reg regs.R) {
	proc.saveAllLiveOperands(code)
}

func (proc *functionCoder) saveLiveRegOperands(code *gen.Coder, t types.T, count int) {
	proc.saveAllLiveOperands(code)
}

func (proc *functionCoder) saveLiveStackOffsetOperand(code *gen.Coder, offset int) {
	proc.saveAllLiveOperands(code)
}

func (proc *functionCoder) saveAllLiveOperands(code *gen.Coder) {
	for _, live := range proc.liveOperands {
		switch live.ref.Storage {
		case values.Reg, values.StackOffset:
			mach.OpPush(code, live.typ, *live.ref)
			*live.ref = values.StackPopOperand

			proc.stackOffset += mach.WordSize()
		}
	}

	if proc.stackOffset > proc.stackUsage {
		proc.stackUsage = proc.stackOffset
	}
}

func (proc *functionCoder) label(code *gen.Coder, l *links.L) {
	l.Address = code.Len()
}

func (proc *functionCoder) branchSite(code *gen.Coder, l *links.L) {
	l.AddSite(code.Len())
	proc.labelLinks[l] = struct{}{}
}

func (proc *functionCoder) callSite(code *gen.Coder, l *links.L) {
	l.AddSite(code.Len())
}

func (proc *functionCoder) pushTarget(l *links.L, name string, expectType types.T) {
	proc.targetStack = append(proc.targetStack, &branchTarget{l, name, expectType, proc.stackOffset})
}

func (proc *functionCoder) popTarget() (live bool) {
	target := proc.targetStack[len(proc.targetStack)-1]
	_, live = proc.labelLinks[target.label]

	proc.targetStack = proc.targetStack[:len(proc.targetStack)-1]
	return
}

func (proc *functionCoder) findTarget(token interface{}) *branchTarget {
	name := token.(string)

	for i := len(proc.targetStack) - 1; i >= 0; i-- {
		target := proc.targetStack[i]
		if target.name != "" && target.name == name {
			return target
		}
	}

	i := int(values.ParseI32(token))
	if i >= 0 && i < len(proc.targetStack) {
		return proc.targetStack[len(proc.targetStack)-i-1]
	}

	panic(name)
}

func (proc *functionCoder) getVarOffsetAndType(name string) (offset int, varType types.T, found bool) {
	v, found := proc.function.Vars[name]
	if !found {
		return
	}

	if v.Param {
		paramPos := proc.function.NumParams - v.Index - 1
		offset = proc.function.NumLocals*mach.WordSize() + mach.FunctionCallStackOverhead() + paramPos*mach.WordSize()
	} else {
		offset = v.Index * mach.WordSize()
	}

	varType = v.Type
	return
}
