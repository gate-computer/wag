package wag

import (
	"bytes"
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

	verbose = false
)

var (
	debugExprDepth = 1
)

type liveOperand struct {
	typ types.T
	ref *values.Operand
}

type regVar struct {
	refs  int
	typ   types.T
	reg   regs.R
	dirty bool
}

type branchTarget struct {
	label       *links.L
	name        string
	expectType  types.T
	stackOffset int
}

type coder struct {
	module *Module

	text   bytes.Buffer
	roData dataArena

	functionLinks map[*Function]*links.L
	trapLinks     gen.TrapLinks

	roFloat32Addrs map[uint32]int
	roFloat64Addrs map[uint64]int

	regsInt   regAllocator
	regsFloat regAllocator

	liveOperands               []liveOperand
	noLiveTempRegOperandsUntil int

	stackOffset int

	targetStack []*branchTarget

	// these must be reset for each function
	function       *Function
	labelLinks     map[*links.L]struct{}
	maxStackOffset int
	varRegs        []regVar
}

func (m *Module) Code() (text, roData, data []byte, bssSize int) {
	code := &coder{
		module:         m,
		roFloat32Addrs: make(map[uint32]int),
		roFloat64Addrs: make(map[uint64]int),
	}

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

				addr := uint32(code.functionLinks[f].FinalAddress())
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

	mach.OpInit(code)

	// generate trap code first so that we can write their addresses as we go.
	// this also ensures that no link address will be zero (if OpInit is nop).

	startFunc := m.NamedFunctions[m.Start]
	startLink := code.functionLinks[startFunc]
	mach.OpBranch(code, 0)
	startLink.AddSite(code.Len()) // XXX: this assumes that call and branch displacements are similar

	code.genTrap(&code.trapLinks.DivideByZero, traps.DivideByZero)
	code.genTrap(&code.trapLinks.CallStackExhausted, traps.CallStackExhausted)
	code.genTrap(&code.trapLinks.IndirectCallIndex, traps.IndirectCallIndex)
	code.genTrap(&code.trapLinks.IndirectCallSignature, traps.IndirectCallSignature)
	code.genTrap(&code.trapLinks.Unreachable, traps.Unreachable)

	code.regsInt.init(mach.AvailableIntRegs())
	code.regsFloat.init(mach.AvailableFloatRegs())

	for _, f := range m.Functions {
		code.genFunction(f)
	}

	for _, link := range code.functionLinks {
		mach.UpdateCalls(code, link)
	}

	roData = code.roData.populate()

	text = code.text.Bytes()
	return
}

func (code *coder) Write(buf []byte) (int, error) {
	return code.text.Write(buf)
}

func (code *coder) WriteByte(b byte) error {
	return code.text.WriteByte(b)
}

func (code *coder) Bytes() []byte {
	return code.text.Bytes()
}

func (code *coder) Len() int {
	return code.text.Len()
}

func (code *coder) TrapLinks() *gen.TrapLinks {
	return &code.trapLinks
}

func (code *coder) genTrap(l *links.L, id traps.Id) {
	l.SetAddress(code.Len())
	mach.OpTrap(code, id)
}

func (code *coder) genFunction(f *Function) {
	if verbose {
		fmt.Printf("<function names=\"%s\">\n", f.Names)
	}

	code.function = f
	code.labelLinks = make(map[*links.L]struct{})
	code.maxStackOffset = 0

	if n := len(f.Params) + len(f.Locals); cap(code.varRegs) >= n {
		code.varRegs = code.varRegs[:n]
	} else {
		code.varRegs = make([]regVar, n)
	}

	mach.AlignFunction(code)
	functionAddr := code.Len()
	stackUsageAddr := mach.OpTrapIfStackExhausted(code)
	stackCheckEndAddr := code.Len()

	stackPtrMoved := false
	zeroIntReg := regs.R(-1)

	for localIndex, localType := range f.Locals {
		varIndex := len(f.Params) + localIndex

		if reg, ok := code.tryAllocReg(localType); ok {
			mach.OpMove(code, localType, reg, values.ImmOperand(localType, 0))
			code.varRegs[varIndex] = regVar{0, localType, reg, true}

			if zeroIntReg < 0 && localType == types.I64 {
				zeroIntReg = reg
			}
		} else {
			if !stackPtrMoved {
				mach.OpAddImmToStackPtr(code, -mach.WordSize()*varIndex)
				stackPtrMoved = true

				if zeroIntReg < 0 {
					zeroIntReg = mach.ResultReg()
					mach.OpMove(code, types.I64, zeroIntReg, values.ImmOperand(types.I64, 0))
				}
			}

			mach.OpPushIntReg(code, zeroIntReg) // assume int 0 == float 0 bit pattern
		}
	}

	if !stackPtrMoved {
		mach.OpAddImmToStackPtr(code, -mach.WordSize()*len(f.Locals))
	}

	end := new(links.L)
	code.pushTarget(end, "", f.Signature.ResultType)

	var result values.Operand
	var resultType types.T
	var deadend bool

	for i, x := range f.body {
		var t types.T
		if i == len(f.body)-1 {
			t = f.Signature.ResultType
		}

		result, resultType, deadend = code.expr(x, t)
		if deadend {
			mach.OpAbort(code)
			break
		}

		if i < len(f.body)-1 {
			code.discard(resultType, result)
		}
	}

	if !deadend {
		code.opMove(f.Signature.ResultType, mach.ResultReg(), result)
	}

	if code.popTarget() {
		deadend = false
		code.opLabel(end)
	}

	stackUsage := len(code.function.Locals)*mach.WordSize() + code.maxStackOffset

	if !deadend {
		mach.OpAddImmToStackPtr(code, len(code.function.Locals)*mach.WordSize())
		mach.OpReturn(code)
	}

	for i, v := range code.varRegs {
		if v.typ != types.Void {
			code.FreeReg(v.typ, v.reg)

			code.varRegs[i].refs = 0
			code.varRegs[i].typ = types.Void
		}
	}

	code.regsInt.postCheck("integer")
	code.regsFloat.postCheck("float")

	if len(code.liveOperands) != 0 {
		panic(errors.New("internal: live operands exist at end of function"))
	}

	if code.stackOffset != 0 {
		panic(fmt.Errorf("internal: stack offset is non-zero at end of function: %d", code.stackOffset))
	}

	if len(code.targetStack) != 0 {
		panic(errors.New("internal: branch target stack is not empty at end of function"))
	}

	for link := range code.labelLinks {
		mach.UpdateBranches(code, link)
	}

	if stackUsage > 0 {
		mach.UpdateStackDisp(code, stackUsageAddr, stackUsage)
	} else {
		newAddr := stackCheckEndAddr &^ (mach.FunctionAlignment() - 1)
		mach.DeleteCode(code, functionAddr, newAddr)
		mach.DisableCode(code, newAddr, stackCheckEndAddr)
		functionAddr = newAddr
	}

	code.functionLinks[f].SetAddress(functionAddr)

	if verbose {
		fmt.Println("</function>")
	}
}

func (code *coder) expr(x interface{}, expectType types.T) (result values.Operand, resultType types.T, deadend bool) {
	expr := x.([]interface{})
	exprName := expr[0].(string)
	args := expr[1:]

	if verbose {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<%s>\n", exprName)
	}
	debugExprDepth++

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
			result, deadend = code.exprUnaryOp(exprName, opName, opType, args)

		case "eq", "gt", "gt_s", "gt_u", "lt", "lt_s", "ne":
			resultType = types.I32
			fallthrough
		case "add", "and", "div", "div_u", "mul", "or", "sub", "xor":
			result, deadend = code.exprBinaryOp(exprName, opName, opType, args)

		case "const":
			result = code.exprConst(exprName, opType, args)

		default:
			panic(exprName)
		}
	} else {
		switch exprName {
		case "block":
			result, deadend = code.exprBlock(exprName, args, expectType, nil)
			resultType = expectType

		case "br", "br_if", "br_table":
			deadend = code.exprBr(exprName, args)

		case "call":
			result, resultType, deadend = code.exprCall(exprName, args)

		case "call_indirect":
			result, resultType, deadend = code.exprCallIndirect(exprName, args)

		case "get_local":
			result, resultType = code.exprGetLocal(exprName, args)

		case "if":
			result, deadend = code.exprIf(exprName, args, expectType)
			resultType = expectType

		case "loop":
			result, deadend = code.exprLoop(exprName, args, expectType)
			resultType = expectType

		case "nop":
			code.exprNop(exprName, args)

		case "return":
			code.exprReturn(exprName, args)
			deadend = true

		case "set_local":
			result, resultType, deadend = code.exprSetLocal(exprName, args)

		case "unreachable":
			code.exprUnreachable(exprName, args)
			deadend = true

		default:
			panic(exprName)
		}
	}

	debugExprDepth--
	if verbose {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("</%s result=\"%s %s\">\n", exprName, resultType, result)
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

	if result.Storage == values.Stack {
		panic(fmt.Errorf("%s: result operand is %s", exprName, result))
	}

	return
}

func (code *coder) exprUnaryOp(exprName, opName string, opType types.T, args []interface{}) (result values.Operand, deadend bool) {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	x, _, deadend := code.expr(args[0], opType)
	if deadend {
		mach.OpAbort(code)
		return
	}

	if value, ok := x.CheckImmValue(opType); ok {
		switch opName {
		case "eqz":
			if value == 0 {
				result = values.ImmOperand(opType, 1)
			} else {
				result = values.ImmOperand(opType, 0)
			}
			return
		}
	}

	result = code.unaryOp(opName, opType, x)
	return
}

func (code *coder) exprBinaryOp(exprName, opName string, opType types.T, args []interface{}) (result values.Operand, deadend bool) {
	if len(args) != 2 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	a, _, deadend := code.expr(args[0], opType)
	if deadend {
		mach.OpAbort(code)
		return
	}

	code.opPushLiveOperand(opType, &a)
	b, _, deadend := code.expr(args[1], opType)
	code.popLiveOperand(&a)
	if deadend {
		code.discard(opType, a)
		mach.OpAbort(code)
		return
	}

	if a.Storage == values.Imm && b.Storage != values.Imm {
		switch opName {
		case "add", "and", "or", "xor":
			a, b = b, a
		}
	}

	if value, ok := b.CheckImmValue(opType); ok && value == 0 {
		switch opName {
		case "add", "or", "sub":
			result = a
			return

		case "mul":
			code.discard(opType, a)
			result = values.ImmOperand(opType, 0)
			return
		}
	}

	result = code.binaryOp(opName, opType, a, b)
	return
}

func (code *coder) exprConst(exprName string, opType types.T, args []interface{}) values.Operand {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	imm := values.ParseImm(opType, args[0])

	// TODO: possible optimization: move RODataOperands to registers in
	//       opPushLiveOperand(), using a RegVar-like operand type.

	switch opType {
	case types.F32:
		if bits := imm.Imm(opType).(uint32); bits != 0 {
			addr, found := code.roFloat32Addrs[bits]
			if !found {
				alloc := code.roData.allocate(4, 4, func(data []byte) {
					mach.ByteOrder().PutUint32(data, bits)
				})
				code.roFloat32Addrs[bits] = alloc.addr
				addr = alloc.addr
			}

			return values.RODataOperand(addr)
		}

	case types.F64:
		if bits := imm.Imm(opType).(uint64); bits != 0 {
			addr, found := code.roFloat64Addrs[bits]
			if !found {
				alloc := code.roData.allocate(8, 8, func(data []byte) {
					mach.ByteOrder().PutUint64(data, bits)
				})
				code.roFloat64Addrs[bits] = alloc.addr
				addr = alloc.addr
			}

			return values.RODataOperand(addr)
		}
	}

	return imm
}

func (code *coder) exprBlock(exprName string, args []interface{}, expectType types.T, before *links.L) (result values.Operand, deadend bool) {
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

	var resultType types.T

	for i, arg := range args {
		var t types.T
		if i == len(args)-1 {
			t = expectType
		}

		result, resultType, deadend = code.expr(arg, t)
		if deadend {
			mach.OpAbort(code)
			break
		}

		if i < len(args)-1 {
			code.discard(resultType, result)
		}
	}

	if before != nil {
		code.popTarget()
	}

	if code.popTarget() {
		if deadend {
			deadend = false
		} else {
			code.opMove(expectType, mach.ResultReg(), result)
		}

		if expectType != types.Void {
			result = values.TempRegOperand(mach.ResultReg())
		}

		code.opLabel(after)
	}

	if deadend {
		mach.OpAbort(code)
	}

	return
}

func (code *coder) exprBr(exprName string, args []interface{}) (deadend bool) {
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

	defaultTarget := code.findTarget(defaultIndex)
	defaultStackDelta := code.stackOffset - defaultTarget.stackOffset

	valueType := defaultTarget.expectType

	var tableTargets []*branchTarget

	for _, x := range tableIndexes {
		target := code.findTarget(x)

		if target.expectType != types.Void {
			switch {
			case valueType == types.Void:
				valueType = target.expectType

			case valueType != target.expectType:
				panic(fmt.Errorf("%s: branch targets have inconsistent types: %s vs. %s", exprName, valueType, target.expectType))
			}
		}

		tableTargets = append(tableTargets, target)

		code.labelLinks[target.label] = struct{}{}
	}

	var valueOperand values.Operand

	if valueExpr != nil {
		valueOperand, _, deadend = code.expr(valueExpr, valueType)
		if deadend {
			mach.OpAbort(code)
			return
		}
	}

	var condOperand values.Operand

	if condExpr != nil {
		code.opPushLiveOperand(valueType, &valueOperand)
		condOperand, _, deadend = code.expr(condExpr, types.I32)
		code.popLiveOperand(&valueOperand)
		if deadend {
			code.discard(valueType, valueOperand)
			mach.OpAbort(code)
			return
		}
	}

	code.opMove(valueType, mach.ResultReg(), valueOperand)

	switch exprName {
	case "br":
		code.opPushTempRegOperands()
		code.opStoreRegVars(true)

		mach.OpAddImmToStackPtr(code, defaultStackDelta)
		code.opBranch(defaultTarget.label)

		deadend = true

	case "br_if":
		code.opPushTempRegOperands()
		code.opStoreRegVars(false)

		mach.OpAddImmToStackPtr(code, defaultStackDelta)
		code.opBranchIf(condOperand, true, defaultTarget.label)
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
		tableAlloc := code.roData.allocate(tableSize, 1<<tableScale, nil)

		code.opPushTempRegOperands()

		var reg2 regs.R

		if commonStackOffset < 0 {
			code.opPushLiveOperand(types.I32, &condOperand)
			reg2 = code.opAllocIntReg()
			defer code.freeIntReg(reg2)
			code.popLiveOperand(&condOperand)
		}

		reg, ok := condOperand.CheckTempReg()
		if !ok {
			// TODO: if condOperand is a regvar, we could just use that if we stored it first

			code.opPushLiveOperand(types.I32, &condOperand)
			reg = code.opAllocIntReg()
			code.popLiveOperand(&condOperand)

			code.opMove(types.I32, reg, condOperand)
		}
		defer code.freeIntReg(reg)

		code.opStoreRegVars(true)

		mach.OpAddImmToStackPtr(code, defaultStackDelta)
		tableStackOffset := code.stackOffset - defaultStackDelta
		code.opBranchIfOutOfBounds(reg, len(tableTargets), defaultTarget.label)
		mach.OpLoadROIntIndex32ScaleDisp(code, tableType, reg, tableScale, tableAlloc.addr, true)

		addrType := types.I64 // loaded with zero-extend

		if commonStackOffset >= 0 {
			mach.OpAddImmToStackPtr(code, tableStackOffset-commonStackOffset)
		} else {
			mach.OpMoveReg(code, types.I64, reg2, reg)
			mach.OpShiftRightLogical32Bits(code, reg2)
			mach.OpAddToStackPtr(code, reg2)

			addrType = types.I32 // upper half of reg still contains stack offset
		}

		branchAddr := mach.OpBranchIndirect(code, addrType, reg)

		tableAlloc.populator = func(data []byte) {
			for _, target := range tableTargets {
				disp := target.label.FinalAddress() - branchAddr

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

func (code *coder) exprCall(exprName string, args []interface{}) (result values.Operand, resultType types.T, deadend bool) {
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

	code.opPushTempRegOperands()

	result, resultType, deadend, argsSize := code.partialCallArgsExpr(exprName, target.Signature, args[1:])
	if deadend {
		mach.OpAbort(code)
		return
	}

	code.opStoreRegVars(true)

	code.opCall(code.functionLinks[target])
	code.opAddImmToStackPtr(argsSize)

	return
}

func (code *coder) exprCallIndirect(exprName string, args []interface{}) (result values.Operand, resultType types.T, deadend bool) {
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

	operand, _, deadend := code.expr(indexExpr, types.I32)
	if deadend {
		mach.OpAbort(code)
		return
	}

	reg, ok := operand.CheckTempReg()
	if !ok {
		code.opPushLiveOperand(types.I32, &operand)
		reg = code.opAllocIntReg()
		defer code.freeIntReg(reg)
		code.popLiveOperand(&operand)

		code.opMove(types.I32, reg, operand)
	}

	code.opPushTempRegOperands()

	// if the operand yielded a temporary register, then it was just freed by
	// the eviction, but the register retains its value.  don't call anything
	// that allocates registers until the critical section ends.

	mach.OpBranchIfOutOfBounds(code, reg, len(code.module.Table), code.trapLinks.IndirectCallIndex.FinalAddress())
	mach.OpLoadROIntIndex32ScaleDisp(code, types.I64, reg, 3, roTableAddr, false)
	mach.OpPushIntReg(code, reg) // push func ptr
	code.incrementStackOffset()
	mach.OpShiftRightLogical32Bits(code, reg) // signature id
	mach.OpBranchIfNotEqualImm32(code, reg, sig.Index, code.trapLinks.IndirectCallSignature.FinalAddress())

	// end of critical section.

	code.opStoreRegVars(true)

	result, resultType, deadend, argsSize := code.partialCallArgsExpr(exprName, sig, args)
	if deadend {
		code.stackOffset -= mach.WordSize() // pop func ptr
		mach.OpAbort(code)
		return
	}

	mach.OpCallIndirectDisp32FromStack(code, argsSize)
	code.opAddImmToStackPtr(argsSize + mach.WordSize()) // pop args and func ptr
	return
}

func (code *coder) partialCallArgsExpr(exprName string, sig *Signature, args []interface{}) (result values.Operand, resultType types.T, deadend bool, argsStackSize int) {
	if len(sig.ArgTypes) != len(args) {
		panic(fmt.Errorf("%s: wrong number of arguments", exprName))
	}

	initialStackOffset := code.stackOffset

	for i, arg := range args {
		t := sig.ArgTypes[i]

		var x values.Operand

		x, _, deadend = code.expr(arg, t)
		if deadend {
			mach.OpAbort(code)
			break
		}

		x = code.opAccessScalar(t, x)
		mach.OpPush(code, t, x)
		code.incrementStackOffset()
	}

	if n := code.stackOffset + mach.FunctionCallStackOverhead(); n > code.maxStackOffset {
		code.maxStackOffset = n
	}

	if deadend {
		code.stackOffset = initialStackOffset
		return
	}

	argsStackSize = code.stackOffset - initialStackOffset

	resultType = sig.ResultType
	if resultType != types.Void {
		result = values.TempRegOperand(mach.ResultReg())
	}
	return
}

func (code *coder) exprGetLocal(exprName string, args []interface{}) (result values.Operand, resultType types.T) {
	if len(args) != 1 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	varName := args[0].(string)
	index, resultType, found := code.lookupFunctionVar(varName)
	if !found {
		panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
	}

	result = values.VarOperand(index)
	return
}

func (code *coder) exprIf(exprName string, args []interface{}, expectType types.T) (result values.Operand, deadend bool) {
	if len(args) < 2 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	haveElse := len(args) == 3

	if len(args) > 3 {
		panic(fmt.Errorf("%s: too many operands", exprName))
	}

	end := new(links.L)
	afterThen := new(links.L)

	ifResult, _, deadend := code.expr(args[0], types.I32)
	if deadend {
		return
	}

	code.opPushTempRegOperands()
	code.opStoreRegVars(false)
	code.opBranchIf(ifResult, false, afterThen)

	thenDeadend, endReachable := code.ifExprs(args[1], "then", end, expectType)

	if haveElse {
		if !thenDeadend {
			code.opPushTempRegOperands()
			code.opStoreRegVars(true)
			code.opBranch(end)
			endReachable = true
		}
		code.opLabel(afterThen)

		elseDeadend, endReachableFromElse := code.ifExprs(args[2], "else", end, expectType)

		if !elseDeadend {
			endReachable = true
		}
		if endReachableFromElse {
			endReachable = true
		}
	} else {
		endReachable = true
		code.opLabel(afterThen)
	}

	if endReachable {
		code.opLabel(end)
	}

	if expectType != types.Void {
		result = values.TempRegOperand(mach.ResultReg())
	}

	deadend = !endReachable
	return
}

func (code *coder) ifExprs(x interface{}, name string, end *links.L, expectType types.T) (deadend, endReached bool) {
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

	code.pushTarget(end, endName, expectType)

	var result values.Operand
	var resultType types.T

	if len(args) > 0 {
		switch args[0].(type) {
		case string:
			result, _, deadend = code.expr(args, expectType)

		case []interface{}:
			for i, expr := range args {
				var t types.T
				if i == len(args)-1 {
					t = expectType
				}

				result, resultType, deadend = code.expr(expr, t)
				if deadend {
					break
				}

				if i < len(args)-1 {
					code.discard(resultType, result)
				}
			}
		}
	}

	if deadend {
		mach.OpAbort(code)
	} else {
		code.opMove(expectType, mach.ResultReg(), result)
	}

	endReached = code.popTarget()

	return
}

func (code *coder) exprLoop(exprName string, args []interface{}, expectType types.T) (result values.Operand, deadend bool) {
	before := new(links.L)
	code.opLabel(before)

	return code.exprBlock(exprName, args, expectType, before)
}

func (code *coder) exprNop(exprName string, args []interface{}) {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}
}

func (code *coder) exprReturn(exprName string, args []interface{}) {
	if len(args) > 1 {
		panic(fmt.Errorf("%s: too many operands", exprName))
	}

	t := code.function.Signature.ResultType

	if t != types.Void && len(args) == 0 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	if len(args) > 0 {
		x, _, deadend := code.expr(args[0], t)
		if deadend {
			mach.OpAbort(code)
			return
		}

		code.opMove(t, mach.ResultReg(), x)
	}

	mach.OpAddImmToStackPtr(code, code.stackOffset+len(code.function.Locals)*mach.WordSize())
	mach.OpReturn(code)
}

func (code *coder) exprSetLocal(exprName string, args []interface{}) (result values.Operand, resultType types.T, deadend bool) {
	if len(args) != 2 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	varName := args[0].(string)
	index, resultType, found := code.lookupFunctionVar(varName)
	if !found {
		panic(fmt.Errorf("%s: variable not found: %s", exprName, varName))
	}

	result, _, deadend = code.expr(args[1], resultType)
	if deadend {
		mach.OpAbort(code)
		return
	}

	// the design doc says that set_local does't return a value, but it's
	// needed for the labels.wast test to work.

	// TODO: repurpose temporary register.  also keep immediates etc.

	if v := code.varRegs[index]; v.typ != types.Void {
		code.opMove(resultType, v.reg, result)
		code.varRegs[index].dirty = true

		result = values.VarOperand(index)
		return
	}

	if reg, ok := code.tryAllocReg(resultType); ok {
		code.opMove(resultType, reg, result)

		v := &code.varRegs[index]
		v.typ = resultType
		v.reg = reg
		v.dirty = true

		result = values.VarOperand(index)
		return
	}

	code.opStoreVar(resultType, index, result)
	result = values.VarOperand(index)
	return
}

func (code *coder) exprUnreachable(exprName string, args []interface{}) {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	mach.OpBranch(code, code.trapLinks.Unreachable.FinalAddress())
}

func (code *coder) unaryOp(name string, t types.T, x values.Operand) values.Operand {
	x = code.opAccessScalar(t, x)
	return mach.UnaryOp(code, name, t, x)
}

func (code *coder) binaryOp(name string, t types.T, a, b values.Operand) values.Operand {
	a = code.opAccessScalar(t, a)
	b = code.opAccessScalar(t, b)
	return mach.BinaryOp(code, name, t, a, b)
}

func (code *coder) OpAllocReg(t types.T) (reg regs.R) {
	reg, ok := code.tryAllocReg(t)
	if !ok {
		reg = code.opStealReg(t)
	}
	return
}

func (code *coder) opTryAllocVarReg(t types.T, refs int) (reg regs.R, ok bool) {
	reg, ok = code.tryAllocReg(t)
	if !ok {
		reg, ok = code.opTryStealVarReg(t, refs)
	}
	return
}

func (code *coder) tryAllocReg(t types.T) (reg regs.R, ok bool) {
	return code.regs(t).allocWithPreference(mach.RegGroupPreference(t))
}

func (code *coder) FreeReg(t types.T, reg regs.R) {
	code.regs(t).free(reg)
}

func (code *coder) opAllocIntReg() (reg regs.R) {
	reg, ok := code.regs(types.I64).alloc()
	if !ok {
		reg = code.opStealReg(types.I64)
	}
	return
}

func (code *coder) freeIntReg(reg regs.R) {
	code.regs(types.I64).free(reg)
}

func (code *coder) regs(t types.T) *regAllocator {
	switch t.Category() {
	case types.Int:
		return &code.regsInt

	case types.Float:
		return &code.regsFloat

	default:
		panic(t)
	}
}

func (code *coder) incrementStackOffset() {
	code.stackOffset += mach.WordSize()
	if code.stackOffset > code.maxStackOffset {
		code.maxStackOffset = code.stackOffset
	}
}

func (code *coder) opAddImmToStackPtr(offset int) {
	code.stackOffset -= offset
	mach.OpAddImmToStackPtr(code, offset)
}

func (code *coder) opBranch(l *links.L) {
	mach.OpBranch(code, l.Address)
	code.branchSite(l)
}

func (code *coder) opBranchIf(x values.Operand, yes bool, l *links.L) {
	x = code.access(types.I32, x)
	mach.OpBranchIf(code, x, yes, l.Address)
	code.branchSite(l)
}

func (code *coder) opBranchIfOutOfBounds(indexReg regs.R, upperBound int, l *links.L) {
	mach.OpBranchIfOutOfBounds(code, indexReg, upperBound, l.Address)
	code.branchSite(l)
}

func (code *coder) opCall(l *links.L) {
	mach.OpCall(code, l.Address)
	code.callSite(l)
}

func (code *coder) opMove(t types.T, target regs.R, x values.Operand) {
	if t == types.Void {
		return
	}

	if target == mach.ResultReg() {
		if reg, ok := x.CheckTempReg(); ok && reg == mach.ResultReg() {
			return
		}
	}

	x = code.access(t, x)
	mach.OpMove(code, t, target, x)
}

func (code *coder) access(t types.T, x values.Operand) values.Operand {
	if x.Storage == values.Stack {
		code.stackOffset -= mach.WordSize()
	}

	return x
}

func (code *coder) opAccessScalar(t types.T, x values.Operand) values.Operand {
	x = code.access(t, x)

	if x.Storage == values.ConditionFlags {
		reg := code.OpAllocReg(t)
		x = mach.OpMove(code, t, reg, x)
	}

	return x
}

func (code *coder) discard(t types.T, x values.Operand) {
	switch x.Storage {
	case values.TempReg:
		code.FreeReg(t, x.Reg())

	case values.Stack:
		code.opAddImmToStackPtr(mach.WordSize())
	}
}

func (code *coder) opPushLiveOperand(t types.T, ref *values.Operand) {
	switch ref.Storage {
	case values.Nowhere, values.Imm, values.ROData:
		return

	case values.Var:
		v := &code.varRegs[ref.Index()]
		v.refs++

		if v.typ == types.Void {
			if reg, ok := code.opTryAllocVarReg(t, v.refs); ok {
				code.opMove(t, reg, *ref)

				v.typ = t
				v.reg = reg
				v.dirty = false
			}
		}

	case values.TempReg:

	case values.ConditionFlags:
		reg := code.OpAllocReg(t)
		code.opMove(t, reg, *ref)
		*ref = values.TempRegOperand(reg)

	default:
		panic(*ref)
	}

	code.liveOperands = append(code.liveOperands, liveOperand{t, ref})
}

func (code *coder) popLiveOperand(ref *values.Operand) {
	switch ref.Storage {
	case values.Nowhere, values.Imm, values.ROData:

	case values.Var:
		v := &code.varRegs[ref.Index()]
		v.refs--
		if v.refs < 0 {
			panic(*ref)
		}
		fallthrough

	case values.TempReg, values.Stack:
		i := len(code.liveOperands) - 1
		live := code.liveOperands[i]

		if live.ref != ref {
			panic("popLiveOperand argument does not match topmost item of liveOperands")
		}

		live.ref = nil
		code.liveOperands = code.liveOperands[:i]

		if code.noLiveTempRegOperandsUntil > i {
			code.noLiveTempRegOperandsUntil = i
		}

	default:
		panic(*ref)
	}
}

// opStealReg doesn't change the allocation state of the register.
func (code *coder) opStealReg(t types.T) regs.R {
	// first, try to commit variable from register to stack

	if reg, ok := code.opTryStealVarReg(t, -1); ok {
		return reg
	}

	// second, push temporary registers to stack until we find the correct type

	for _, live := range code.liveOperands[code.noLiveTempRegOperandsUntil:] {
		if reg, ok := live.ref.CheckTempReg(); ok {
			x := code.opAccessScalar(live.typ, *live.ref)
			mach.OpPush(code, live.typ, x)
			code.incrementStackOffset()
			*live.ref = values.StackOperand

			if live.typ.Category() == t.Category() {
				return reg
			}
		}

		code.noLiveTempRegOperandsUntil++
	}

	panic("no registers to steal")
}

// opTryStealVarReg doesn't change the allocation state of the register.
func (code *coder) opTryStealVarReg(t types.T, refsLimit int) (reg regs.R, ok bool) {
	varRefs := refsLimit
	var varIndex int

	for i, v := range code.varRegs {
		if v.typ.Category() == t.Category() {
			if v.refs < 0 || v.refs < varRefs {
				varRefs = v.refs
				varIndex = i
			}
		}
	}

	if varRefs == refsLimit {
		return
	}

	v := &code.varRegs[varIndex]

	if v.dirty {
		code.opStoreVar(v.typ, varIndex, values.VarOperand(varIndex)) // XXX: this is ugly
	}
	v.typ = types.Void

	reg = v.reg
	ok = true
	return
}

func (code *coder) opPushTempRegOperands() {
	pushed := false

	for _, live := range code.liveOperands[code.noLiveTempRegOperandsUntil:] {
		switch live.ref.Storage {
		case values.TempReg:
			x := code.opAccessScalar(live.typ, *live.ref)
			mach.OpPush(code, live.typ, x)
			code.incrementStackOffset()
			*live.ref = values.StackOperand

			pushed = true

		case values.Stack:
			if pushed {
				panic("previously pushed operand found after newly pushed operand")
			}
		}
	}

	code.noLiveTempRegOperandsUntil = len(code.liveOperands)
}

// opStoreRegVars is only safe when there are no live RegVar operands.
func (code *coder) opStoreRegVars(forgetRegs bool) {
	for i, v := range code.varRegs {
		if v.typ != types.Void {
			if v.dirty {
				code.opStoreVar(v.typ, i, values.VarOperand(i)) // XXX: this is ugly
				code.varRegs[i].dirty = false
			}

			if forgetRegs {
				code.varRegs[i].typ = types.Void
				code.FreeReg(v.typ, v.reg)
			}
		}
	}
}

func (code *coder) opStoreVar(t types.T, index int, x values.Operand) {
	offset := code.varStackOffset(index)
	x = code.opAccessScalar(t, x)
	mach.OpStoreStack(code, t, offset, x)
}

func (code *coder) opLabel(l *links.L) {
	code.opPushTempRegOperands()
	code.opStoreRegVars(true)
	l.SetAddress(code.Len())

	if verbose {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Println("<label/>")
	}
}

func (code *coder) branchSite(l *links.L) {
	if l.Address == 0 {
		l.AddSite(code.Len())
		code.labelLinks[l] = struct{}{}
	}
}

func (code *coder) callSite(l *links.L) {
	if l.Address == 0 {
		l.AddSite(code.Len())
	}
}

func (code *coder) pushTarget(l *links.L, name string, expectType types.T) {
	code.targetStack = append(code.targetStack, &branchTarget{l, name, expectType, code.stackOffset})
}

func (code *coder) popTarget() (live bool) {
	target := code.targetStack[len(code.targetStack)-1]
	_, live = code.labelLinks[target.label]

	code.targetStack = code.targetStack[:len(code.targetStack)-1]
	return
}

func (code *coder) findTarget(token interface{}) *branchTarget {
	name := token.(string)

	for i := len(code.targetStack) - 1; i >= 0; i-- {
		target := code.targetStack[i]
		if target.name != "" && target.name == name {
			return target
		}
	}

	i := int(values.ParseI32(token))
	if i >= 0 && i < len(code.targetStack) {
		return code.targetStack[len(code.targetStack)-i-1]
	}

	panic(name)
}

func (code *coder) Var(i int) (offset int, reg regs.R, regOk bool) {
	if v := code.varRegs[i]; v.typ == types.Void {
		offset = code.varStackOffset(i)
	} else {
		reg = v.reg
		regOk = true
	}
	return
}

func (code *coder) varStackOffset(index int) int {
	var offset int

	if index < len(code.function.Params) {
		pos := len(code.function.Params) - index - 1
		offset = len(code.function.Locals)*mach.WordSize() + mach.FunctionCallStackOverhead() + pos*mach.WordSize()
	} else {
		offset = (index - len(code.function.Params)) * mach.WordSize()
	}

	return code.stackOffset + offset
}

func (code *coder) lookupFunctionVar(name string) (index int, typ types.T, found bool) {
	v, found := code.function.Vars[name]
	if !found {
		return
	}

	if v.Param {
		index = v.Index
	} else {
		index = len(code.function.Params) + v.Index
	}

	typ = v.Type
	return
}
