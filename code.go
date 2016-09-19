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

type varState struct {
	refCount int
	cache    values.Operand
	dirty    bool
}

func (v *varState) init(x values.Operand, dirty bool) {
	v.cache = x
	v.dirty = dirty
}

func (v *varState) reset() {
	v.init(values.NoOperand, false)
}

type branchTarget struct {
	label       *links.L
	name        string
	expectType  types.T
	stackOffset int
	functionEnd bool
}

type coder struct {
	module *Module

	text       bytes.Buffer
	roData     dataArena
	roDataAddr int

	functionLinks map[*Function]*links.L
	trapLinks     gen.TrapLinks

	roFloat32Addrs map[uint32]int
	roFloat64Addrs map[uint64]int

	regsInt   regAllocator
	regsFloat regAllocator

	liveOperands          []liveOperand
	immutableLiveOperands int

	targetStack []*branchTarget

	// these must be reset for each function
	function       *Function
	vars           []varState
	pushedLocals   int
	stackOffset    int
	maxStackOffset int
}

func (m *Module) Code(roDataAddr int32, roDataBuf []byte) (text, roData, data []byte) {
	code := &coder{
		module:         m,
		roDataAddr:     int(roDataAddr),
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

	roData = code.roData.populate(roDataBuf)

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

func (code *coder) RODataAddr() int {
	return code.roDataAddr
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

	if n := len(f.Params) + len(f.Locals); cap(code.vars) >= n {
		code.vars = code.vars[:n]
	} else {
		code.vars = make([]varState, n)
	}

	for local, t := range f.Locals {
		index := len(f.Params) + local
		code.vars[index].init(values.ImmOperand(t, 0), true)
	}

	code.pushedLocals = 0
	code.stackOffset = 0
	code.maxStackOffset = 0

	mach.AlignFunction(code)
	functionAddr := code.Len()
	stackUsageAddr := mach.OpTrapIfStackExhausted(code)
	stackCheckEndAddr := code.Len()

	end := new(links.L)
	code.pushTarget(end, "", f.Signature.ResultType, true)

	var result values.Operand
	var resultType types.T
	var deadend bool

	for i, x := range f.body {
		final := i == len(f.body)-1

		var t types.T
		if final {
			t = f.Signature.ResultType
		}

		result, resultType, deadend = code.expr(x, t, final, 0, nil)
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
		mach.UpdateBranches(code, end)
	}

	if !deadend {
		code.opAddImmToStackPtr(code.stackOffset)
		mach.OpReturn(code)
	}

	for i := range code.vars {
		v := &code.vars[i]

		if v.refCount != 0 {
			panic(fmt.Errorf("internal: variable #%d reference count is non-zero at end of function", i))
		}

		if reg, ok := v.cache.CheckVarReg(); ok {
			code.FreeReg(code.varType(i), reg)
		}

		v.reset()
	}

	code.regsInt.postCheck("integer")
	code.regsFloat.postCheck("float")

	if len(code.liveOperands) != 0 {
		panic(errors.New("internal: live operands exist at end of function"))
	}

	if len(code.targetStack) != 0 {
		panic(errors.New("internal: branch target stack is not empty at end of function"))
	}

	if code.maxStackOffset > 0 {
		mach.UpdateStackDisp(code, stackUsageAddr, code.maxStackOffset)
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

func (code *coder) expr(x interface{}, expectType types.T, final bool, liveType types.T, liveOperand *values.Operand) (result values.Operand, resultType types.T, deadend bool) {
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

	if liveOperand != nil {
		switch exprName {
		case "i32.const", "i64.const", "f32.const", "f64.const", "get_local", "nop", "unreachable":
			// no side-effects

		default:
			code.opPushLiveOperand(liveType, liveOperand)
			defer code.popLiveOperand(liveOperand)
		}
	}

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
			result, deadend = code.exprBlock(exprName, args, expectType, nil, final)
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
			result, deadend = code.exprIf(exprName, args, expectType, final)
			resultType = expectType

		case "loop":
			result, deadend = code.exprLoop(exprName, args, expectType, final)
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

	x, _, deadend := code.expr(args[0], opType, false, 0, nil)
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

	a, _, deadend := code.expr(args[0], opType, false, 0, nil)
	if deadend {
		mach.OpAbort(code)
		return
	}

	b, _, deadend := code.expr(args[1], opType, false, opType, &a)
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

	if value, ok := b.CheckImmValue(opType); ok {
		switch opName {
		case "add", "or", "sub", "xor":
			switch value {
			case 0:
				result = a
				return
			}

		case "mul":
			switch value {
			case 0:
				code.discard(opType, a)
				result = values.ImmOperand(opType, 0)
				return

			case 1:
				result = a
				return
			}
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

func (code *coder) exprBlock(exprName string, args []interface{}, expectType types.T, before *links.L, final bool) (result values.Operand, deadend bool) {
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
	code.pushTarget(after, afterName, expectType, final)

	if before != nil {
		code.pushTarget(before, beforeName, types.Void, false)
	}

	var resultType types.T

	for i, arg := range args {
		var t types.T
		if i == len(args)-1 {
			t = expectType
		}

		result, resultType, deadend = code.expr(arg, t, false, 0, nil)
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
		mach.UpdateBranches(code, after)
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

	valueType := defaultTarget.expectType

	var tableTargets []*branchTarget

	for _, x := range tableIndexes {
		target := code.findTarget(x)
		target.label.SetLive()

		if target.expectType != types.Void {
			switch {
			case valueType == types.Void:
				valueType = target.expectType

			case valueType != target.expectType:
				panic(fmt.Errorf("%s: branch targets have inconsistent types: %s vs. %s", exprName, valueType, target.expectType))
			}
		}

		tableTargets = append(tableTargets, target)
	}

	var valueOperand values.Operand

	if valueExpr != nil {
		valueOperand, _, deadend = code.expr(valueExpr, valueType, false, 0, nil)
		if deadend {
			mach.OpAbort(code)
			return
		}
	}

	var condOperand values.Operand

	if condExpr != nil {
		condOperand, _, deadend = code.expr(condExpr, types.I32, false, valueType, &valueOperand)
		if deadend {
			code.discard(valueType, valueOperand)
			mach.OpAbort(code)
			return
		}
	}

	code.opMove(valueType, mach.ResultReg(), valueOperand)

	switch exprName {
	case "br":
		if defaultTarget.functionEnd {
			mach.OpAddImmToStackPtr(code, code.stackOffset)
			mach.OpReturn(code)
		} else {
			code.opSaveTempRegOperands()
			code.opInitLocals()
			code.opStoreRegVars(true)

			delta := code.stackOffset - defaultTarget.stackOffset

			mach.OpAddImmToStackPtr(code, delta)
			code.opBranch(defaultTarget.label)
		}

		deadend = true

	case "br_if":
		code.opSaveTempRegOperands()
		code.opInitLocals()
		code.opStoreRegVars(false)

		delta := code.stackOffset - defaultTarget.stackOffset

		mach.OpAddImmToStackPtr(code, delta)
		code.opBranchIf(condOperand, true, defaultTarget.label)
		mach.OpAddImmToStackPtr(code, -delta)

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

		code.opSaveTempRegOperands()

		var reg2 regs.R

		if commonStackOffset < 0 {
			reg2 = code.opAllocIntReg(types.I32, &condOperand)
			defer code.freeIntReg(reg2)
		}

		var reg regs.R
		var ok bool

		index, isVar := condOperand.CheckVar()
		if isVar {
			if v := code.vars[index]; v.cache.Storage == values.VarReg {
				reg = v.cache.Reg()
				ok = true
			}
		} else {
			reg, ok = condOperand.CheckTempReg()
			if ok {
				defer code.freeIntReg(reg)
			}
		}
		if !ok {
			reg = code.opAllocIntReg(types.I32, &condOperand)
			defer code.freeIntReg(reg)

			code.opMove(types.I32, reg, condOperand)
		}

		code.opInitLocals()
		code.opStoreRegVars(true)

		// if condOperand yielded a var register, then it was just freed by the
		// storing of vars, but the register retains its value.  don't call
		// anything that allocates registers until the critical section ends.

		defaultDelta := code.stackOffset - defaultTarget.stackOffset

		mach.OpAddImmToStackPtr(code, defaultDelta)
		tableStackOffset := code.stackOffset - defaultDelta
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

		// end of critical section.

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

	code.opSaveTempRegOperands()
	code.opInitLocals()

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

	operand, _, deadend := code.expr(indexExpr, types.I32, false, 0, nil)
	if deadend {
		mach.OpAbort(code)
		return
	}

	reg, ok := operand.CheckTempReg()
	if !ok {
		reg = code.opAllocIntReg(types.I32, &operand)
		defer code.freeIntReg(reg)

		code.opMove(types.I32, reg, operand)
	}

	code.opSaveTempRegOperands()
	code.opInitLocals()

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

		x, _, deadend = code.expr(arg, t, false, 0, nil)
		if deadend {
			mach.OpAbort(code)
			break
		}

		x = code.effectiveOperand(x)
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

	v := &code.vars[index]

	switch v.cache.Storage {
	case values.Imm, values.ROData:
		result = v.cache

	case values.Nowhere, values.VarReg:
		result = values.VarOperand(index)

	default:
		panic(v.cache)
	}

	return
}

func (code *coder) exprIf(exprName string, args []interface{}, expectType types.T, final bool) (result values.Operand, deadend bool) {
	if len(args) < 2 {
		panic(fmt.Errorf("%s: too few operands", exprName))
	}

	haveElse := len(args) == 3

	if len(args) > 3 {
		panic(fmt.Errorf("%s: too many operands", exprName))
	}

	ifResult, _, deadend := code.expr(args[0], types.I32, false, 0, nil)
	if deadend {
		return
	}

	code.opSaveTempRegOperands()
	code.opInitLocals()
	code.opStoreRegVars(false)

	end := new(links.L)
	var endReachable bool

	if haveElse {
		afterElse := new(links.L)
		code.opBranchIf(ifResult, true, afterElse)

		elseDeadend, endReachableFromElse := code.ifExprs(args[2], "else", end, expectType, final)
		if !elseDeadend {
			if final {
				mach.OpAddImmToStackPtr(code, code.stackOffset)
				mach.OpReturn(code)
			} else {
				code.opSaveTempRegOperands()
				code.opStoreRegVars(true)
				code.opBranch(end)
				endReachable = true
			}
		}
		if endReachableFromElse {
			endReachable = true
		}

		code.opLabel(afterElse)
		mach.UpdateBranches(code, afterElse)
	} else {
		code.opBranchIf(ifResult, false, end)
		endReachable = true
	}

	thenDeadend, endReachableFromThen := code.ifExprs(args[1], "then", end, expectType, final)
	if !thenDeadend {
		endReachable = true
	}
	if endReachableFromThen {
		endReachable = true
	}

	if endReachable {
		code.opLabel(end)
		mach.UpdateBranches(code, end)

		if expectType != types.Void {
			result = values.TempRegOperand(mach.ResultReg())
		}
	} else {
		deadend = true
	}
	return
}

func (code *coder) ifExprs(x interface{}, name string, end *links.L, expectType types.T, final bool) (deadend, endReached bool) {
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

	code.pushTarget(end, endName, expectType, final)

	var result values.Operand
	var resultType types.T

	if len(args) > 0 {
		switch args[0].(type) {
		case string:
			result, _, deadend = code.expr(args, expectType, false, 0, nil)

		case []interface{}:
			for i, expr := range args {
				var t types.T
				if i == len(args)-1 {
					t = expectType
				}

				result, resultType, deadend = code.expr(expr, t, false, 0, nil)
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

func (code *coder) exprLoop(exprName string, args []interface{}, expectType types.T, final bool) (result values.Operand, deadend bool) {
	before := new(links.L)
	code.opLabel(before)
	defer mach.UpdateBranches(code, before)

	return code.exprBlock(exprName, args, expectType, before, final)
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
		x, _, deadend := code.expr(args[0], t, true, 0, nil)
		if deadend {
			mach.OpAbort(code)
			return
		}

		code.opMove(t, mach.ResultReg(), x)
	}

	mach.OpAddImmToStackPtr(code, code.stackOffset)
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

	result, _, deadend = code.expr(args[1], resultType, false, 0, nil)
	if deadend {
		mach.OpAbort(code)
		return
	}

	if oldIndex, ok := result.CheckVar(); ok && index == oldIndex {
		return
	}

	v := &code.vars[index]
	oldCache := v.cache

	if v.refCount > 0 {
		switch oldCache.Storage {
		case values.Nowhere, values.VarReg:
			for i := len(code.liveOperands) - 1; i >= code.immutableLiveOperands; i-- {
				live := code.liveOperands[i]
				if live.ref.Storage == values.Var && live.ref.Index() == index {
					reg, ok := code.TryAllocReg(resultType)
					if !ok {
						goto push
					}

					code.opMove(resultType, reg, *live.ref) // TODO: avoid multiple loads
					*live.ref = values.TempRegOperand(reg)

					v.refCount--
					if v.refCount == 0 {
						goto done
					}
					if v.refCount < 0 {
						panic("inconsistent variable reference count")
					}
				}
			}
			break

		push:
			code.opInitLocals()

			for _, live := range code.liveOperands[code.immutableLiveOperands:] {
				if live.ref.Storage == values.Var && live.ref.Index() == index {
					x := code.effectiveOperand(*live.ref)
					mach.OpPush(code, resultType, x) // TODO: avoid multiple loads
					code.incrementStackOffset()
					*live.ref = values.StackOperand

					v.refCount--
					if v.refCount == 0 {
						goto done
					}
					if v.refCount < 0 {
						panic("inconsistent variable reference count")
					}
				}
			}

		done:
		}

		if v.refCount != 0 {
			panic("could not find all variable references")
		}
	}

	switch result.Storage {
	case values.Imm, values.ROData:
		v.cache = result
		v.dirty = true

	case values.Var, values.Stack, values.ConditionFlags:
		reg, ok := oldCache.CheckVarReg()
		if ok {
			// reusing cache register, don't free it
			oldCache = values.NoOperand
		} else {
			reg, ok = code.opTryAllocVarReg(resultType)
		}

		if ok {
			code.opMove(resultType, reg, result)
			v.cache = values.VarRegOperand(index, reg)
			v.dirty = true
		} else {
			code.opStoreVar(resultType, index, result)
			v.cache = values.NoOperand
			v.dirty = false
		}

	case values.TempReg:
		var ok bool

		reg := result.Reg()
		if code.regAllocated(resultType, reg) {
			// repurposing the register which already contains the value
			ok = true
		} else {
			// can't keep the transient register which contains the value

			reg, ok = oldCache.CheckVarReg()
			if ok {
				// reusing cache register, don't free it
				oldCache = values.NoOperand
			} else {
				reg, ok = code.opTryAllocVarReg(resultType)
			}

			if ok {
				// we got a register for the value
				code.opMove(resultType, reg, result)
			}
		}

		if ok {
			v.cache = values.VarRegOperand(index, reg)
			v.dirty = true
		} else {
			code.opStoreVar(resultType, index, result)
			v.cache = values.NoOperand
			v.dirty = false
		}

	default:
		panic(result)
	}

	switch oldCache.Storage {
	case values.Nowhere, values.Imm, values.ROData:

	case values.VarReg:
		code.FreeReg(resultType, oldCache.Reg())

	default:
		panic(oldCache)
	}

	// the design doc says that set_local does't return a value, but it's
	// needed for the labels.wast test to work.
	result = code.virtualOperand(v.cache)
	return
}

func (code *coder) exprUnreachable(exprName string, args []interface{}) {
	if len(args) != 0 {
		panic(fmt.Errorf("%s: wrong number of operands", exprName))
	}

	mach.OpBranch(code, code.trapLinks.Unreachable.FinalAddress())
}

func (code *coder) unaryOp(name string, t types.T, x values.Operand) (result values.Operand) {
	x = code.effectiveOperand(x)
	result = mach.UnaryOp(code, name, t, x)
	result = code.virtualOperand(result)
	return
}

func (code *coder) binaryOp(name string, t types.T, a, b values.Operand) (result values.Operand) {
	a = code.opMaterializeOperand(t, a)
	b = code.effectiveOperand(b)
	result = mach.BinaryOp(code, name, t, a, b)
	result = code.virtualOperand(result)
	return
}

func (code *coder) TryAllocReg(t types.T) (reg regs.R, ok bool) {
	return code.regs(t).allocWithPreference(mach.RegGroupPreference(t))
}

func (code *coder) opAllocReg(t types.T) (reg regs.R) {
	reg, ok := code.TryAllocReg(t)
	if !ok {
		reg = code.opStealReg(t)
	}
	return
}

func (code *coder) opTryAllocVarReg(t types.T) (reg regs.R, ok bool) {
	reg, ok = code.TryAllocReg(t)
	if !ok {
		reg, ok = code.opTryStealVarReg(t)
	}
	return
}

func (code *coder) FreeReg(t types.T, reg regs.R) {
	code.regs(t).free(reg)
}

func (code *coder) tryAllocIntReg() (reg regs.R, ok bool) {
	return code.regs(types.I64).alloc()
}

func (code *coder) opAllocIntReg(liveType types.T, liveOperand *values.Operand) (reg regs.R) {
	reg, ok := code.tryAllocIntReg()
	if !ok {
		if liveOperand != nil {
			code.opPushLiveOperand(liveType, liveOperand)
			defer code.popLiveOperand(liveOperand)
		}

		reg = code.opStealReg(types.I64)
	}

	return
}

func (code *coder) freeIntReg(reg regs.R) {
	code.regs(types.I64).free(reg)
}

// regAllocated indicates if we can hang onto a register returned by mach ops.
func (code *coder) regAllocated(t types.T, reg regs.R) bool {
	return code.regs(t).allocated(reg)
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

func (code *coder) opInitLocals() {
	code.opInitLocalsUntil(len(code.function.Locals), values.NoOperand)
}

func (code *coder) opInitLocalsUntil(lastLocal int, lastValue values.Operand) {
	var haveZero bool
	var zeroReg regs.R

	for local := code.pushedLocals; local <= lastLocal && local < len(code.function.Locals); local++ {
		index := len(code.function.Params) + local

		v := &code.vars[index]
		x := v.cache
		if x.Storage == values.Nowhere {
			panic("variable without cached value during locals initialization")
		}
		if !v.dirty {
			panic("variable not dirty during locals initialization")
		}

		if local == lastLocal {
			x = lastValue
		}

		t := code.function.Locals[local]

		if value, ok := x.CheckImmValue(types.I64); ok && value == 0 {
			if !haveZero {
				zeroReg, haveZero = code.tryAllocIntReg()
				if haveZero {
					defer code.freeIntReg(zeroReg)
					code.opMove(t, zeroReg, values.ImmOperand(t, 0))
				}
			}

			if haveZero {
				mach.OpPushIntReg(code, zeroReg)
				goto pushed
			}
		}

		mach.OpPush(code, t, x)

	pushed:
		code.incrementStackOffset()
		v.dirty = false

		code.pushedLocals++
	}
}

func (code *coder) incrementStackOffset() {
	code.stackOffset += mach.WordSize()
	if code.stackOffset > code.maxStackOffset {
		code.maxStackOffset = code.stackOffset
	}
}

func (code *coder) AddStackUsage(size int) {
	if n := code.stackOffset + size; n > code.maxStackOffset {
		code.maxStackOffset = n
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
	x = code.effectiveOperand(x)
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
	if t == types.Void || x.Storage == values.Nowhere {
		return
	}

	x = code.effectiveOperand(x)

	if target == mach.ResultReg() {
		if reg, ok := x.CheckTempReg(); ok && reg == mach.ResultReg() {
			return
		}
	}

	mach.OpMove(code, t, target, x)
}

func (code *coder) opMaterializeOperand(t types.T, x values.Operand) values.Operand {
	x = code.effectiveOperand(x)

	switch x.Storage {
	case values.Stack, values.ConditionFlags:
		reg := code.opAllocReg(t)
		code.opMove(t, reg, x)
		x = values.TempRegOperand(reg)
	}

	return x
}

func (code *coder) effectiveOperand(x values.Operand) values.Operand {
	if x.Storage == values.Var {
		i := x.Index()
		if v := code.vars[i]; v.cache.Storage == values.Nowhere {
			x = values.VarMemOperand(i, code.effectiveVarStackOffset(i))
		} else {
			x = v.cache
		}
	}

	return x
}

func (code *coder) virtualOperand(x values.Operand) values.Operand {
	switch x.Storage {
	case values.VarMem, values.VarReg:
		x = x.VarOperand()
	}

	return x
}

func (code *coder) Consumed(t types.T, x values.Operand) {
	switch x.Storage {
	case values.TempReg:
		code.FreeReg(t, x.Reg())

	case values.Stack:
		code.stackOffset -= mach.WordSize()
	}
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
		i := ref.Index()
		v := &code.vars[i]
		v.refCount++

		if v.cache.Storage == values.Nowhere {
			if reg, ok := code.opTryAllocVarReg(t); ok {
				code.opMove(t, reg, *ref)
				v.cache = values.VarRegOperand(i, reg)
				v.dirty = false
			}
		}

	case values.TempReg:
		if code.regAllocated(t, ref.Reg()) {
			break // ok
		}
		fallthrough // can't keep the transient register

	case values.ConditionFlags:
		reg := code.opAllocReg(t)
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
		v := &code.vars[ref.Index()]
		v.refCount--
		if v.refCount < 0 {
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

		if code.immutableLiveOperands > i {
			code.immutableLiveOperands = i
		}

	default:
		panic(*ref)
	}
}

// opStealReg doesn't change the allocation state of the register.
func (code *coder) opStealReg(needType types.T) (reg regs.R) {
	// first, try to commit unreferenced variable from register to stack

	reg, ok := code.opTryStealUnusedVarReg(needType)
	if ok {
		return
	}

	// second, push variables and registers to stack until we find the correct type

	for _, live := range code.liveOperands[code.immutableLiveOperands:] {
		var found bool

		typeMatch := (live.typ.Category() == needType.Category())

		switch live.ref.Storage {
		case values.Imm, values.ROData:

		case values.Var:
			index := live.ref.Index()
			v := &code.vars[index]

			found = typeMatch && (v.cache.Storage == values.VarReg) && (v.refCount == 1)
			if found {
				if v.dirty {
					code.opStoreVar(live.typ, index, values.VarOperand(index)) // XXX: this is ugly
				}
				reg = v.cache.Reg()
				v.reset()
			} else {
				code.opInitLocals()

				x := code.effectiveOperand(*live.ref)
				mach.OpPush(code, live.typ, x)
				code.incrementStackOffset()
				*live.ref = values.StackOperand
			}

			v.refCount--
			if v.refCount < 0 {
				panic(*live.ref)
			}

		case values.TempReg:
			code.opInitLocals()

			found = typeMatch
			reg = live.ref.Reg()
			x := code.effectiveOperand(*live.ref)
			mach.OpPush(code, live.typ, x)
			code.incrementStackOffset()
			*live.ref = values.StackOperand

		default:
			panic(*live.ref)
		}

		code.immutableLiveOperands++

		if found {
			return
		}
	}

	panic("no registers to steal")
}

// opTryStealVarReg doesn't change the allocation state of the register.
func (code *coder) opTryStealVarReg(needType types.T) (reg regs.R, ok bool) {
	reg, ok = code.opTryStealUnusedVarReg(needType)
	if ok {
		return
	}

	for _, live := range code.liveOperands[code.immutableLiveOperands:] {
		switch live.ref.Storage {
		case values.Imm, values.ROData:

		case values.Var:
			if live.typ.Category() != needType.Category() {
				return // nope
			}

			index := live.ref.Index()
			v := &code.vars[index]
			if v.refCount > 1 {
				return // nope
			}
			if v.cache.Storage != values.VarReg {
				return // nope
			}

			if v.dirty {
				code.opStoreVar(live.typ, index, values.VarOperand(index)) // XXX: this is ugly
			}
			reg = v.cache.Reg()
			v.reset()

			v.refCount--
			if v.refCount < 0 {
				panic(*live.ref)
			}

			ok = true

		case values.TempReg:
			return // nope

		default:
			panic(*live.ref)
		}

		code.immutableLiveOperands++

		if ok {
			return
		}
	}

	return
}

// opTryStealUnusedVarReg doesn't change the allocation state of the register.
// Locals must have been pushed already.
func (code *coder) opTryStealUnusedVarReg(needType types.T) (reg regs.R, ok bool) {
	var i int
	var v *varState
	var t types.T

	for i = range code.vars {
		v = &code.vars[i]
		if v.refCount == 0 && v.cache.Storage == values.VarReg {
			t = code.varType(i)
			if t.Category() == needType.Category() {
				goto found
			}
		}
	}

	return

found:
	if v.dirty {
		code.opStoreVar(t, i, values.VarOperand(i)) // XXX: this is ugly
	}
	reg = v.cache.Reg()
	v.reset()
	ok = true
	return
}

func (code *coder) opSaveTempRegOperands() {
	pushed := false

	for _, live := range code.liveOperands[code.immutableLiveOperands:] {
		switch live.ref.Storage {
		case values.TempReg:
			code.opInitLocals()

			x := code.effectiveOperand(*live.ref)
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

	code.immutableLiveOperands = len(code.liveOperands)
}

// opStoreRegVars is only safe when there are no live Var operands.
func (code *coder) opStoreRegVars(forget bool) {
	for i := range code.vars {
		v := &code.vars[i]
		t := code.varType(i)

		if v.dirty {
			code.opStoreVar(t, i, values.VarOperand(i)) // XXX: this is ugly
			v.dirty = false
		}

		if forget {
			if v.cache.Storage == values.VarReg {
				code.FreeReg(t, v.cache.Reg())
			}
			v.reset()
		}
	}
}

func (code *coder) opStoreVar(t types.T, index int, x values.Operand) {
	x = code.effectiveOperand(x)
	if local := index - len(code.function.Params); local >= code.pushedLocals {
		code.opInitLocalsUntil(local, x)
	} else {
		offset := code.effectiveVarStackOffset(index)
		mach.OpStoreStack(code, t, offset, x)
	}
}

func (code *coder) opLabel(l *links.L) {
	code.opSaveTempRegOperands()
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
	}
}

func (code *coder) callSite(l *links.L) {
	if l.Address == 0 {
		l.AddSite(code.Len())
	}
}

func (code *coder) pushTarget(l *links.L, name string, expectType types.T, functionEnd bool) {
	offset := code.stackOffset

	if code.pushedLocals < len(code.function.Locals) {
		// init still in progress, but any branch expressions will have
		// initialized all locals
		offset = len(code.function.Locals) * mach.WordSize()
	}

	code.targetStack = append(code.targetStack, &branchTarget{l, name, expectType, offset, functionEnd})
}

func (code *coder) popTarget() (live bool) {
	target := code.targetStack[len(code.targetStack)-1]
	live = target.label.Live()

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

func (code *coder) varType(index int) types.T {
	if index < len(code.function.Params) {
		return code.function.Params[index]
	} else {
		return code.function.Locals[index-len(code.function.Params)]
	}
}

func (code *coder) effectiveVarStackOffset(index int) int {
	var offset int

	if index < len(code.function.Params) {
		pos := len(code.function.Params) - index - 1
		offset = code.stackOffset + mach.FunctionCallStackOverhead() + pos*mach.WordSize()
	} else {
		index -= len(code.function.Params)
		offset = code.stackOffset - (index+1)*mach.WordSize()
	}

	if offset < 0 {
		panic("effective stack offset is negative")
	}

	return offset
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
