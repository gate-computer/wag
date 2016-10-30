package wag

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/types"
	"github.com/tsavola/wag/wasm"
)

type moduleCoder struct {
	*Module
}

func (m moduleCoder) globalOffset(index uint32) int32 {
	return (int32(index) - int32(len(m.globals))) * gen.WordSize
}

func (m moduleCoder) genCode(r reader, startTrigger chan<- struct{}) {
	if debug {
		if debugDepth != 0 {
			debugf("")
		}
		debugDepth = 0
	}

	if !m.startDefined {
		panic(errors.New("start function not defined"))
	}

	if m.roDataAbsAddr <= 0 {
		panic(fmt.Errorf("invalid read-only memory address: %d", m.roDataAbsAddr))
	}

	if m.text == nil {
		m.text = new(bytes.Buffer)
	}

	funcCodeCount := r.readVaruint32()
	if needed := len(m.funcSigs) - len(m.importFuncs); funcCodeCount != uint32(needed) {
		panic(fmt.Errorf("wrong number of function bodies: %d (should be: %d)", funcCodeCount, needed))
	}

	m.funcLinks = make([]links.FunctionL, len(m.funcSigs))

	if m.roData.alloc(int32(len(m.tableFuncs))*8, 8) != gen.ROTableAddr {
		panic("table could not be allocated at designated read-only memory offset")
	}

	m.genTrapEntry(traps.MissingFunction) // at zero address

	link := &m.funcLinks[m.startIndex]
	retAddr := mach.OpInit(m, link.Addr)
	m.mapCallAddr(retAddr, 0)
	link.AddSite(retAddr)
	// start function returns here, and proceeds to execute the exit trap

	for id := traps.Exit; id < traps.NumTraps; id++ {
		if id != traps.MissingFunction {
			m.genTrapEntry(id)
		}
	}

	for i, imp := range m.importFuncs {
		addr := m.genImportEntry(imp)
		m.funcLinks[i].Addr = addr
	}

	m.regs.init(mach.AvailRegs())

	var midpoint int

	if machNative && startTrigger != nil {
		midpoint = int(m.startIndex) + 1
	} else {
		midpoint = len(m.funcSigs)
	}

	for i := len(m.importFuncs); i < midpoint; i++ {
		code := funcCoder{moduleCoder: m}
		code.genFunction(r, i)

		mach.UpdateCalls(code, &m.funcLinks[i].L)
	}

	ptr := m.roData.buf[gen.ROTableAddr:]

	for i, funcIndex := range m.tableFuncs {
		link := &m.funcLinks[funcIndex]

		sigIndex := m.funcSigs[funcIndex]
		funcAddr := uint32(link.Addr) // missing if not generated yet
		binary.LittleEndian.PutUint64(ptr[:8], (uint64(sigIndex)<<32)|uint64(funcAddr))
		ptr = ptr[8:]

		if funcAddr == 0 {
			link.AddTableIndex(i)
		}
	}

	if startTrigger != nil {
		close(startTrigger)
	}

	if midpoint < len(m.funcSigs) {
		for i := midpoint; i < len(m.funcSigs); i++ {
			code := funcCoder{moduleCoder: m}
			code.genFunction(r, i)
		}

		mach.ClearInsnCache()

		for i := midpoint; i < len(m.funcSigs); i++ {
			link := &m.funcLinks[i]
			addr := uint32(link.Addr)

			for _, tableIndex := range link.TableIndexes {
				offset := gen.ROTableAddr + tableIndex*8
				mach.PutUint32(m.roData.buf[offset:offset+4], addr) // overwrite only function addr
			}

			mach.UpdateCalls(m, &link.L)
		}

		mach.ClearInsnCache()
	}
}

func (m moduleCoder) Write(buf []byte) (int, error) {
	return m.text.Write(buf)
}

func (m moduleCoder) WriteByte(b byte) error {
	return m.text.WriteByte(b)
}

func (m moduleCoder) Align(alignment int, padding byte) {
	size := (alignment - m.text.Len()) & (alignment - 1)
	m.text.Grow(size)
	for i := 0; i < size; i++ {
		m.text.WriteByte(padding)
	}
}

func (m moduleCoder) Bytes() []byte {
	return m.text.Bytes()
}

func (m moduleCoder) Len() int32 {
	return int32(m.text.Len())
}

func (m moduleCoder) MinMemorySize() wasm.MemorySize {
	return wasm.MemorySize(m.memoryLimits.initial)
}

func (m moduleCoder) RODataAddr() int32 {
	return m.roDataAbsAddr
}

func (m moduleCoder) TrapEntryAddr(id traps.Id) int32 {
	return m.trapLinks[id].FinalAddr()
}

func (m moduleCoder) mapCallAddr(retAddr, stackOffset int32) {
	entry := (uint64(stackOffset) << 32) | uint64(retAddr)
	debugf("map call: retAddr=0x%x stackOffset=%d", retAddr, stackOffset)
	if err := binary.Write(&m.callMap, binary.LittleEndian, uint64(entry)); err != nil {
		panic(err)
	}
}

func (m moduleCoder) genTrapEntry(id traps.Id) {
	m.trapLinks[id].Addr = m.Len()
	mach.OpEnterTrapHandler(m, id)
}

func (m moduleCoder) genImportEntry(imp importFunction) (addr int32) {
	if debug {
		debugf("import function")
		debugDepth++
	}

	m.Align(mach.FunctionAlignment(), mach.PaddingByte())
	addr = m.Len()
	m.mapFunctionAddr(addr)

	sigIndex := m.funcSigs[imp.funcIndex]
	sig := m.sigs[sigIndex]

	if imp.variadic {
		var paramRegs regIterator
		numStackParams := paramRegs.init(mach.ParamRegs(), sig.Args)
		if numStackParams > 0 {
			panic("import function has stack parameters")
		}

		for i := range sig.Args {
			t := sig.Args[i]
			reg := paramRegs.iterForward(gen.TypeRegCategory(t))
			mach.OpStoreStackReg(m, t, -(int32(i)+1)*gen.WordSize, reg)
		}
	}

	mach.OpEnterImportFunction(m, imp.absAddr, imp.variadic, len(sig.Args), int(sigIndex))

	if debug {
		debugDepth--
		debugf("imported function")
	}

	return
}

func (m moduleCoder) mapFunctionAddr(addr int32) {
	debugf("map function: addr=0x%x", addr)
	if err := binary.Write(&m.funcMap, binary.LittleEndian, addr); err != nil {
		panic(err)
	}
}

type varState struct {
	cache       values.Operand
	refCount    int
	dirty       bool
	boundsStack []values.Bounds
}

func (v *varState) resetCache() {
	v.cache = values.NoOperand(v.cache.Type)
	v.dirty = false
}

func (v *varState) trimBoundsStack(size int) {
	if len(v.boundsStack) > size {
		v.boundsStack = v.boundsStack[:size]
	}
}

type branchTarget struct {
	label       links.L
	stackOffset int32
	valueType   types.T
	functionEnd bool
}

type branchTable struct {
	roDataAddr      int32
	targets         []*branchTarget
	codeStackOffset int32 // -1 indicates common offset
}

type trampoline struct {
	stackOffset int32
	link        links.L
}

type funcCoder struct {
	moduleCoder

	resultType types.T

	vars           []varState
	numStackParams int32
	numInitedVars  int32

	stackOffset    int32
	maxStackOffset int32
	stackCheckAddr int32

	operands              []values.Operand
	minBlockOperand       int
	numStableOperands     int
	numPersistentOperands int

	branchTargets []*branchTarget
	branchTables  []branchTable

	trapTrampolines [traps.NumTraps]trampoline
}

func (code *funcCoder) TryAllocReg(t types.T) (reg regs.R, ok bool) {
	return code.regs.alloc(gen.TypeRegCategory(t))
}

func (code *funcCoder) AllocSpecificReg(t types.T, reg regs.R) {
	code.regs.allocSpecific(gen.TypeRegCategory(t), reg)
}

func (code *funcCoder) FreeReg(t types.T, reg regs.R) {
	code.regs.free(gen.TypeRegCategory(t), reg)
}

// RegAllocated indicates if we can hang onto a register returned by mach ops.
func (code *funcCoder) RegAllocated(t types.T, reg regs.R) bool {
	return code.regs.allocated(gen.TypeRegCategory(t), reg)
}

func (code *funcCoder) mapCallAddr(retAddr int32) {
	code.moduleCoder.mapCallAddr(retAddr, code.stackOffset+gen.WordSize)
}

func (code *funcCoder) effectiveOperand(x values.Operand) values.Operand {
	if x.Storage == values.VarReference {
		index := x.VarIndex()
		v := code.vars[index]

		if v.cache.Storage == values.Nowhere {
			x = values.VarMemOperand(x.Type, index, code.effectiveVarStackOffset(index))
		} else {
			x = v.cache
		}

		if i := len(v.boundsStack) - 1; i >= 0 {
			x = x.WithBounds(v.boundsStack[i])
		}
	}

	return x
}

func (code *funcCoder) Consumed(x values.Operand) {
	switch x.Storage {
	case values.TempReg:
		code.FreeReg(x.Type, x.Reg())

	case values.Stack:
		code.stackOffset -= gen.WordSize

		debugf("stack offset: %d", code.stackOffset)
	}
}

func (code *funcCoder) Discard(x values.Operand) {
	switch x.Storage {
	case values.TempReg:
		code.FreeReg(x.Type, x.Reg())

	case values.Stack:
		code.opBackoffStackPtr(gen.WordSize)
	}
}

func (code *funcCoder) effectiveVarStackOffset(index int32) (offset int32) {
	if index < code.numStackParams {
		paramPos := code.numStackParams - index - 1
		// account for the function return address
		offset = code.stackOffset + gen.WordSize + paramPos*gen.WordSize
	} else {
		regParamIndex := index - code.numStackParams
		offset = code.stackOffset - (regParamIndex+1)*gen.WordSize
	}

	if offset < 0 {
		panic("effective stack offset is negative")
	}
	return
}

func (code *funcCoder) branchSites(l *links.L, retAddrs ...int32) {
	if l.Addr == 0 {
		for _, addr := range retAddrs {
			l.AddSite(addr)
		}
	}
}

func (code *funcCoder) pushBranchTarget(valueType types.T, functionEnd bool) {
	stackOffset := code.stackOffset

	if int(code.numInitedVars) < len(code.vars) {
		// init still in progress, but any branch expressions will have
		// initialized all vars before we reach the target
		numRegParams := int32(len(code.vars)) - code.numStackParams
		stackOffset = numRegParams * gen.WordSize
	}

	code.branchTargets = append(code.branchTargets, &branchTarget{
		stackOffset: stackOffset,
		valueType:   valueType,
		functionEnd: functionEnd,
	})
}

func (code *funcCoder) popBranchTarget() (finalizedLabel *links.L) {
	n := len(code.branchTargets) - 1
	finalizedLabel = &code.branchTargets[n].label
	code.branchTargets = code.branchTargets[:n]

	code.trimBoundsStacks()
	return
}

func (code *funcCoder) getBranchTarget(depth uint32) *branchTarget {
	if depth >= uint32(len(code.branchTargets)) {
		panic(fmt.Errorf("relative branch depth out of bounds: %d", depth))
	}
	return code.branchTargets[len(code.branchTargets)-int(depth)-1]
}

func (code *funcCoder) boundsStackLevel() int {
	return len(code.branchTargets)
}

func (code *funcCoder) trimBoundsStacks() {
	size := code.boundsStackLevel() + 1
	for i := range code.vars {
		code.vars[i].trimBoundsStack(size)
	}
}

func (code *funcCoder) updateMemoryIndex(index values.Operand, offset uint32, oper uint16) {
	if index.Storage.IsVar() {
		v := &code.vars[index.VarIndex()]

		if v.cache.Storage == values.VarReg && !v.cache.RegZeroExt() {
			// LoadOp and StoreOp make sure that index gets zero-extended if it's a VarReg operand
			v.cache = values.VarRegOperand(v.cache.Type, v.cache.VarIndex(), v.cache.Reg(), true)
		}

		if offset < math.MaxUint16 { // ignore accesses at large offsets
			size := oper >> 8

			begin := uint16(offset)
			end := begin + size
			if end < begin {
				end = math.MaxUint16
			}

			// enlarge the stack

			level := code.boundsStackLevel()

			currSize := len(v.boundsStack)
			needSize := level + 1

			if currSize < needSize {
				if cap(v.boundsStack) >= needSize {
					v.boundsStack = v.boundsStack[:needSize]
				} else {
					buf := make([]values.Bounds, needSize)
					copy(buf, v.boundsStack)
					v.boundsStack = buf
				}

				var lastValue values.Bounds
				if currSize > 0 {
					lastValue = v.boundsStack[currSize-1]
				}

				for i := currSize; i < needSize; i++ {
					v.boundsStack[i] = lastValue
				}
			}

			// update the bounds

			bounds := &v.boundsStack[level]

			if !bounds.Defined() {
				bounds.Lower = begin
				bounds.Upper = end
			} else {
				if begin < bounds.Lower {
					bounds.Lower = begin
				}
				if end > bounds.Upper {
					bounds.Upper = end
				}
			}

			debugf("variable #%d bounds set to [%d,%d)", index.VarIndex(), bounds.Lower, bounds.Upper)
		}
	}
}

func (code *funcCoder) TrapTrampolineAddr(id traps.Id) (addr int32) {
	t := &code.trapTrampolines[id]
	if t.stackOffset == code.stackOffset {
		addr = t.link.Addr
	}
	return
}

func (code *funcCoder) genFunction(r reader, funcIndex int) {
	sigIndex := code.funcSigs[funcIndex]
	sig := code.sigs[sigIndex]

	if debug {
		debugf("function %d %s", funcIndex-len(code.importFuncs), sig)
		debugDepth++
	}

	r.readVaruint32() // body size

	code.Align(mach.FunctionAlignment(), mach.PaddingByte())
	addr := code.Len()
	code.funcLinks[funcIndex].Addr = addr
	code.mapFunctionAddr(addr)

	code.resultType = sig.Result

	code.vars = make([]varState, len(sig.Args))

	var paramRegs regIterator
	code.numStackParams = paramRegs.init(mach.ParamRegs(), sig.Args)
	code.numInitedVars = code.numStackParams // they're already there

	for i := 0; i < int(code.numStackParams); i++ {
		code.vars[i].cache = values.NoOperand(sig.Args[i])
	}

	for i := code.numStackParams; i < int32(len(sig.Args)); i++ {
		t := sig.Args[i]
		cat := gen.TypeRegCategory(t)
		reg := paramRegs.iterForward(cat)
		code.regs.allocSpecific(cat, reg)
		code.vars[i] = varState{
			cache: values.VarRegOperand(t, i, reg, false),
			dirty: true,
		}
	}

	for range r.readCount() {
		params := r.readCount()
		if uint64(len(code.vars))+uint64(len(params)) >= maxFunctionVars {
			panic(errors.New("function with too many variables"))
		}

		t := types.ByEncoding(r.readVaruint7())

		for range params {
			code.vars = append(code.vars, varState{
				cache: values.ImmOperand(t, 0),
				dirty: true,
			})
		}
	}

	code.pushBranchTarget(code.resultType, true)

	deadend := code.genOps(r)

	if code.minBlockOperand != 0 {
		panic("minimum operand index is not zero at end of function")
	}

	if deadend {
		for len(code.operands) > 0 {
			x := code.popOperand()
			debugf("discarding operand at end of function due to deadend: %s", x)
			code.Discard(x)
		}
	} else if code.resultType != types.Void {
		result := code.popOperand()
		if result.Type != code.resultType {
			panic(fmt.Errorf("function result operand type is %s, but function result type is %s", result.Type, code.resultType))
		}
		code.opMove(mach.ResultReg(), result, false)
	}

	if end := code.popBranchTarget(); end.Live() {
		code.opLabel(end)
		mach.UpdateBranches(code, end)
		deadend = false
	}

	if !deadend {
		code.opBackoffStackPtr(code.stackOffset)
		mach.OpReturn(code)
	}

	if len(code.operands) != 0 {
		debugf("operand stack: %v", code.operands)
		panic(errors.New("operand stack is not empty at end of function"))
	}

	if len(code.branchTargets) != 0 {
		panic("branch target stack is not empty at end of function")
	}

	for i := range code.vars {
		v := code.vars[i]
		if v.refCount != 0 {
			panic("variable reference count is non-zero at end of function")
		}
		if v.cache.Storage == values.VarReg {
			code.FreeReg(v.cache.Type, v.cache.Reg())
		}
	}

	code.regs.assertNoneAllocated()

	if debug {
		debugDepth--
		if debugDepth != 0 {
			panic("OMG")
		}
		if deadend {
			debugf("functioned to deadend")
		} else {
			debugf("functioned")
		}
	}

	if code.stackCheckAddr != 0 {
		mach.UpdateStackCheck(code, code.stackCheckAddr, code.maxStackOffset)
	}

	for _, table := range code.branchTables {
		buf := code.roData.buf[table.roDataAddr:]
		for _, target := range table.targets {
			targetAddr := uint32(target.label.FinalAddr())
			if table.codeStackOffset < 0 {
				// common offset
				binary.LittleEndian.PutUint32(buf[:4], targetAddr)
				buf = buf[4:]
			} else {
				delta := table.codeStackOffset - target.stackOffset
				packed := (uint64(uint32(delta)) << 32) | uint64(targetAddr)
				binary.LittleEndian.PutUint64(buf[:8], packed)
				buf = buf[8:]
			}
		}
	}

	return
}

func (code *funcCoder) genOps(r reader) (deadend bool) {
	if debug {
		debugf("{")
		debugDepth++
	}

	for {
		op := r.readOpcode()

		if op == opcodeEnd {
			break
		}

		deadend = code.genOp(r, op)
		if deadend {
			skipOps(r)
			break
		}
	}

	if debug {
		debugDepth--
		debugf("}")
	}
	return
}

func skipOps(r reader) {
	for {
		op := r.readOpcode()

		if op == opcodeEnd {
			return
		}

		skipOp(r, op)
	}
}

func (code *funcCoder) genThenOps(r reader) (deadend, haveElse bool) {
	if debug {
		debugf("{")
		debugDepth++
	}

loop:
	for {
		op := r.readOpcode()

		switch op {
		case opcodeEnd:
			break loop

		case opcodeElse:
			haveElse = true
			break loop
		}

		deadend = code.genOp(r, op)
		if deadend {
			haveElse = skipThenOps(r)
			break loop
		}
	}

	if debug {
		debugDepth--
		debugf("}")
	}
	return
}

func skipThenOps(r reader) (haveElse bool) {
	for {
		op := r.readOpcode()

		switch op {
		case opcodeEnd:
			return

		case opcodeElse:
			haveElse = true
			return
		}

		skipOp(r, op)
	}
}

func (code *funcCoder) genOp(r reader, op opcode) (deadend bool) {
	if debug {
		debugf("%s op", op)
		debugDepth++
	}

	impl := opcodeImpls[op]
	deadend = impl.gen(code, r, op, impl.info)

	if debug {
		debugDepth--
		if deadend {
			debugf("%s operated to deadend", op)
		} else {
			debugf("%s operated", op)
		}
	}

	return
}

func skipOp(r reader, op opcode) {
	debugf("skipping %s", op)
	opcodeSkips[op](r, op)
}

func genBinaryConditionOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.opStackCheck() // before we create ConditionFlags operand
	return genBinaryOp(code, r, op, info)
}

func genBinaryOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	right := code.opMaterializeOperand(code.popOperand())
	left := code.opMaterializeOperand(code.popOperand())

	code.genBinaryOp(op, left, right, info)
	return
}

func genBinaryConditionCommuteOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.opStackCheck() // before we create ConditionFlags operand
	return genBinaryCommuteOp(code, r, op, info)
}

func genBinaryCommuteOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	right := code.opMaterializeOperand(code.popOperand())
	left := code.opMaterializeOperand(code.popOperand())

	if left.Storage == values.Imm {
		left, right = right, left
	}

	code.genBinaryOp(op, left, right, info)
	return
}

func (code *funcCoder) genBinaryOp(op opcode, left, right values.Operand, info opInfo) {
	if t := info.primaryType(); left.Type != t || right.Type != t {
		panic(fmt.Errorf("%s operands have wrong types: %s, %s", op, left.Type, right.Type))
	}

	code.opStabilizeOperandStack()
	result := mach.BinaryOp(code, info.oper(), left, right)
	code.pushOperand(result)
}

func genConstI32(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.pushImmOperand(types.I32, uint64(int64(r.readVarint32())))
	return
}

func genConstI64(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.pushImmOperand(types.I64, uint64(r.readVarint64()))
	return
}

func genConstF32(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.pushImmOperand(types.F32, uint64(r.readUint32()))
	return
}

func genConstF64(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.pushImmOperand(types.F64, r.readUint64())
	return
}

func genConversionOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	x := code.opMaterializeOperand(code.popOperand())
	if x.Type != info.secondaryType() {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	code.opStabilizeOperandStack()
	result := mach.ConversionOp(code, info.oper(), info.primaryType(), x)
	code.pushOperand(result)
	return
}

func genLoadOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	virtualIndex := code.popOperand()
	if virtualIndex.Type != types.I32 {
		panic(fmt.Errorf("%s index has wrong type: %s", op, virtualIndex.Type))
	}

	index := code.opMaterializeOperand(virtualIndex)

	r.readVaruint32() // flags
	offset := r.readVaruint32()

	code.opStabilizeOperandStack()
	result := mach.LoadOp(code, info.oper(), index, info.primaryType(), offset)
	code.updateMemoryIndex(virtualIndex, offset, info.oper())
	code.pushOperand(result)
	return
}

func genStoreOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	value := code.opMaterializeOperand(code.popOperand())
	if value.Type != info.primaryType() {
		panic(fmt.Errorf("%s value has wrong type: %s", op, value.Type))
	}

	virtualIndex := code.opMaterializeOperand(code.popOperand())
	if virtualIndex.Type != types.I32 {
		panic(fmt.Errorf("%s index has wrong type: %s", op, virtualIndex.Type))
	}

	index := code.opMaterializeOperand(virtualIndex)

	r.readVaruint32() // flags
	offset := r.readVaruint32()

	code.opStabilizeOperandStack()
	mach.StoreOp(code, info.oper(), index, value, offset)
	code.updateMemoryIndex(virtualIndex, offset, info.oper())
	return
}

func genUnaryConditionOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.opStackCheck() // before we create ConditionFlags operand
	return genUnaryOp(code, r, op, info)
}

func genUnaryOp(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	x := code.opMaterializeOperand(code.popOperand())
	if x.Type != info.primaryType() {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	code.opStabilizeOperandStack()
	result := mach.UnaryOp(code, info.oper(), x)
	code.pushOperand(result)
	return
}

func genBlock(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	t := types.InlineSignatureByEncoding(r.readVaruint7())

	code.pushBranchTarget(t, false) // end

	savedMinBlockOperand := code.minBlockOperand
	code.minBlockOperand = len(code.operands)

	deadend = code.genOps(r)

	var result values.Operand

	if deadend {
		for len(code.operands) > code.minBlockOperand {
			x := code.popOperand()
			debugf("discarding operand at end of %s due to deadend: %s", op, x)
			code.Discard(x)
		}
	} else {
		if t != types.Void {
			result = code.popOperand()
			if result.Type != t {
				panic(fmt.Errorf("%s result has wrong type: %s", op, result.Type))
			}
		}

		if len(code.operands) != code.minBlockOperand {
			panic(fmt.Errorf("operands remain on stack after %s", op))
		}
	}

	code.minBlockOperand = savedMinBlockOperand

	if end := code.popBranchTarget(); end.Live() {
		if result.Storage != values.Nowhere {
			code.opMove(mach.ResultReg(), result, false)
		}

		if t != types.Void {
			result = values.TempRegOperand(t, mach.ResultReg(), false)
		}

		code.opLabel(end)
		mach.UpdateBranches(code, end)
		deadend = false
	}

	if result.Storage != values.Nowhere {
		code.pushOperand(result)
	}

	return
}

func skipBlock(r reader, op opcode) {
	r.readVaruint7() // inline signature type
	skipOps(r)
}

func genBr(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	relativeDepth := r.readVaruint32()
	target := code.getBranchTarget(relativeDepth)

	if target.valueType != types.Void {
		value := code.popOperand()
		if value.Type != target.valueType {
			panic(fmt.Errorf("%s value operand type is %s, but target expects %s", op, value.Type, target.valueType))
		}
		code.opMove(mach.ResultReg(), value, false)
	}

	if target.functionEnd {
		mach.OpAddImmToStackPtr(code, code.stackOffset)
		mach.OpReturn(code)
	} else {
		code.opSaveTemporaryOperands() // TODO: avoid saving operands which we are going to skip over
		code.opInitVars()
		code.opStoreVars(true)
		mach.OpAddImmToStackPtr(code, code.stackOffset-target.stackOffset)
		code.opBranch(&target.label)
	}

	deadend = true
	return
}

func genBrIf(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	relativeDepth := r.readVaruint32()
	target := code.getBranchTarget(relativeDepth)

	cond := code.opPreloadOperand(code.popOperand())
	if cond.Type != types.I32 {
		panic(fmt.Errorf("%s: condition operand has wrong type: %s", op, cond.Type))
	}

	var value values.Operand

	if target.valueType != types.Void {
		value = code.popOperand()
		if value.Type != target.valueType {
			panic(fmt.Errorf("%s: value operand has wrong type: %s", op, value.Type))
		}
	}

	code.opSaveTemporaryOperands()
	code.opInitVars()
	code.opStoreVars(false)

	if value.Type != types.Void {
		if cond.Storage == values.TempReg && cond.Reg() == mach.ResultReg() {
			reg := code.opAllocReg(types.I32)
			zeroExt := code.opMove(reg, cond, true)
			cond = values.TempRegOperand(cond.Type, reg, zeroExt)
		}

		code.opMove(mach.ResultReg(), value, true)
	}

	stackDelta := code.stackOffset - target.stackOffset

	mach.OpAddImmToStackPtr(code, stackDelta)
	code.opBranchIf(cond, true, &target.label)
	mach.OpAddImmToStackPtr(code, -stackDelta)

	if target.valueType != types.Void {
		code.pushResultRegOperand(target.valueType)
	}
	return
}

func genBrTable(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	targetCount := r.readVaruint32()
	if targetCount >= uint32(maxBranchTableSize) {
		panic(fmt.Errorf("%s has too many targets: %d", op, targetCount))
	}

	targetTable := make([]*branchTarget, targetCount)

	for i := range targetTable {
		relativeDepth := r.readVaruint32()
		target := code.getBranchTarget(relativeDepth)
		target.label.SetLive()
		targetTable[i] = target
	}

	relativeDepth := r.readVaruint32()
	defaultTarget := code.getBranchTarget(relativeDepth)
	defaultTarget.label.SetLive()

	index := code.opPreloadOperand(code.popOperand())
	if index.Type != types.I32 {
		panic(fmt.Errorf("%s: index operand has wrong type: %s", op, index.Type))
	}

	valueType := defaultTarget.valueType

	for i, target := range targetTable {
		if target.valueType != valueType {
			panic(fmt.Errorf("%s targets have inconsistent value types: %s (default target) vs. %s (target #%d)", op, valueType, target.valueType, i))
		}
	}

	var value values.Operand

	if valueType != types.Void {
		value = code.popOperand()
		if value.Type != valueType {
			panic(fmt.Errorf("%s: value operand has wrong type: %s", op, value.Type))
		}
	}

	var commonStackOffset int32
	var tableType = types.I32
	var tableScale uint8 = 2

	if len(targetTable) > 0 {
		commonStackOffset = targetTable[0].stackOffset
		for _, target := range targetTable[1:] {
			if target.stackOffset != commonStackOffset {
				commonStackOffset = -1
				tableType = types.I64
				tableScale = 3
				break
			}
		}
	}

	tableSize := int32(len(targetTable)) << tableScale
	tableAddr := code.roData.alloc(tableSize, 1<<tableScale)

	code.opSaveTemporaryOperands() // TODO: avoid saving operands which we are going to skip over?
	code.opInitVars()
	code.opStoreVars(false)

	var reg2 regs.R

	if commonStackOffset < 0 {
		reg2 = code.opAllocReg(types.I32)
	}

	if value.Type != types.Void {
		if index.Storage == values.TempReg && index.Reg() == mach.ResultReg() {
			reg := code.opAllocReg(types.I32)
			zeroExt := code.opMove(reg, index, true)
			index = values.TempRegOperand(index.Type, reg, zeroExt)
		}

		code.opMove(mach.ResultReg(), value, true)
	}

	var reg regs.R
	var regZeroExt bool

	if index.Storage.IsReg() {
		reg = index.Reg()
		regZeroExt = index.RegZeroExt()
	} else {
		reg = code.opAllocReg(types.I32)
		regZeroExt = mach.OpMove(code, reg, index, false)
	}

	code.regs.freeAll()

	// vars were already stored and regs freed
	for i := range code.vars {
		code.vars[i].resetCache()
	}

	// if index yielded a var register, then it was just freed, but the
	// register retains its value.  don't call anything that allocates
	// registers until the critical section ends.

	defaultDelta := code.stackOffset - defaultTarget.stackOffset

	mach.OpAddImmToStackPtr(code, defaultDelta)
	tableStackOffset := code.stackOffset - defaultDelta
	code.opBranchIfOutOfBounds(reg, int32(len(targetTable)), &defaultTarget.label)
	regZeroExt = mach.OpLoadROIntIndex32ScaleDisp(code, tableType, reg, regZeroExt, tableScale, tableAddr)

	if commonStackOffset >= 0 {
		mach.OpAddImmToStackPtr(code, tableStackOffset-commonStackOffset)
	} else {
		mach.OpMoveReg(code, types.I64, reg2, reg)
		mach.OpShiftRightLogical32Bits(code, reg2)
		mach.OpAddToStackPtr(code, reg2)

		regZeroExt = false
	}

	mach.OpBranchIndirect32(code, reg, regZeroExt)

	// end of critical section.

	t := branchTable{
		roDataAddr: tableAddr,
		targets:    targetTable,
	}
	if commonStackOffset >= 0 {
		t.codeStackOffset = -1
	} else {
		// no common offset
		t.codeStackOffset = tableStackOffset
	}
	code.branchTables = append(code.branchTables, t)

	deadend = true
	return
}

func skipBrTable(r reader, op opcode) {
	for range r.readCount() {
		r.readVaruint32() // target
	}
	r.readVaruint32() // default target
}

func genCall(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	funcIndex := r.readVaruint32()
	if funcIndex >= uint32(len(code.funcSigs)) {
		panic(fmt.Errorf("%s: function index out of bounds: %d", op, funcIndex))
	}

	sigIndex := code.funcSigs[funcIndex]
	sig := code.sigs[sigIndex]

	numStackParams := code.setupCallOperands(op, sig, values.Operand{})

	code.opCall(&code.funcLinks[funcIndex].L)
	code.opBackoffStackPtr(numStackParams * gen.WordSize)
	return
}

func genCallIndirect(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	sigIndex := r.readVaruint32()
	if sigIndex >= uint32(len(code.sigs)) {
		panic(fmt.Errorf("%s: signature index out of bounds: %d", op, sigIndex))
	}

	sig := code.sigs[sigIndex]

	r.readVaruint1() // reserved

	funcIndex := code.opMaterializeOperand(code.popOperand())
	if funcIndex.Type != types.I32 {
		panic(fmt.Errorf("%s: function index operand has wrong type: %s", op, funcIndex.Type))
	}

	numStackParams := code.setupCallOperands(op, sig, funcIndex)

	// if funcIndex is a reg, it was already relocated to result reg.
	// otherwise it wasn't touched.
	if !funcIndex.Storage.IsReg() {
		code.opMove(mach.ResultReg(), funcIndex, false)
	}

	retAddr := mach.OpCallIndirect(code, int32(len(code.tableFuncs)), int32(sigIndex))
	code.mapCallAddr(retAddr)
	code.opBackoffStackPtr(numStackParams * gen.WordSize)
	return
}

func skipCallIndirect(r reader, op opcode) {
	r.readVaruint32() // type index
	r.readVaruint1()  // reserved
}

func (code *funcCoder) setupCallOperands(op opcode, sig types.Function, indirect values.Operand) (numStackParams int32) {
	code.opStackCheck()

	args := code.popOperands(len(sig.Args))

	code.opInitVars()
	code.opSaveTemporaryOperands()
	code.opStoreRegVars()

	var regArgs regMap

	for i, value := range args {
		if value.Type != sig.Args[i] {
			panic(fmt.Errorf("%s argument #%d has wrong type: %s", op, i, value.Type))
		}

		var reg regs.R
		var ok bool

		switch value.Storage {
		case values.TempReg:
			reg = value.Reg()
			ok = true

		case values.VarReference:
			if x := code.vars[value.VarIndex()].cache; x.Storage == values.VarReg {
				reg = x.Reg()
				ok = true
				args[i] = x // help the next args loop
			}
		}

		if ok {
			regArgs.set(gen.TypeRegCategory(value.Type), reg, i)
		}
	}

	code.regs.freeAll()

	// relocate indirect index to result reg if it already occupies some reg
	if indirect.Storage.IsReg() && indirect.Reg() != mach.ResultReg() {
		if i := regArgs.get(gen.RegCategoryInt, mach.ResultReg()); i >= 0 {
			debugf("indirect call index: %s <-> %s", mach.ResultReg(), indirect)
			mach.OpSwap(code, gen.RegCategoryInt, mach.ResultReg(), indirect.Reg())

			args[i] = values.TempRegOperand(args[i].Type, indirect.Reg(), args[i].RegZeroExt())
			regArgs.clear(gen.RegCategoryInt, mach.ResultReg())
			regArgs.set(gen.RegCategoryInt, indirect.Reg(), i)
		} else {
			debugf("indirect call index: %s <- %s", mach.ResultReg(), indirect)
			mach.OpMoveReg(code, types.I32, mach.ResultReg(), indirect.Reg())
		}
	}

	var paramRegs regIterator
	numStackParams = paramRegs.init(mach.ParamRegs(), sig.Args)

	var numMissingStackArgs int32

	for _, x := range args[:numStackParams] {
		if x.Storage != values.Stack {
			numMissingStackArgs++
		}
	}

	if numMissingStackArgs > 0 {
		code.opAdvanceStackPtr(numMissingStackArgs * gen.WordSize)

		sourceIndex := numMissingStackArgs
		targetIndex := int32(0)

		// move the register args forward which are currently on stack
		for i := int32(len(args)) - 1; i >= numStackParams; i-- {
			if args[i].Storage == values.Stack {
				debugf("call param #%d: stack (temporary) <- %s", i, args[i])
				mach.OpCopyStack(code, targetIndex*gen.WordSize, sourceIndex*gen.WordSize)
				sourceIndex++
				targetIndex++
			}
		}

		// move the stack args forward which are already on stack, while
		// inserting the missing stack args
		for i := numStackParams - 1; i >= 0; i-- {
			x := args[i]

			switch x.Storage {
			case values.Stack:
				debugf("call param #%d: stack <- %s", i, x)
				mach.OpCopyStack(code, targetIndex*gen.WordSize, sourceIndex*gen.WordSize)
				sourceIndex++

			default:
				x = code.effectiveOperand(x)
				debugf("call param #%d: stack <- %s", i, x)
				mach.OpStoreStack(code, targetIndex*gen.WordSize, x)
			}

			targetIndex++
		}
	}

	var preserveFlags bool

	for i := numStackParams; i < int32(len(args)); i++ {
		value := args[i]
		cat := gen.TypeRegCategory(value.Type)
		posReg := paramRegs.iterForward(cat)

		switch {
		case value.Storage.IsReg(): // Vars backed by RegVars were replaced by earlier loop
			valueReg := value.Reg()
			if valueReg == posReg {
				debugf("call param #%d: %s %s already in place", i, cat, posReg)
			} else {
				if otherArgIndex := regArgs.get(cat, posReg); otherArgIndex >= 0 {
					debugf("call param #%d: %s %s <-> %s", i, cat, posReg, value)
					mach.OpSwap(code, cat, posReg, valueReg)

					args[otherArgIndex] = value
					regArgs.set(cat, valueReg, otherArgIndex)
				} else {
					debugf("call param #%d: %s %s <- %s", i, cat, posReg, value)
					mach.OpMoveReg(code, value.Type, posReg, valueReg)
				}
			}

		case value.Storage == values.ConditionFlags:
			preserveFlags = true
		}
	}

	paramRegs.initRegs(mach.ParamRegs())

	for i := int32(len(args)) - 1; i >= numStackParams; i-- {
		value := args[i]
		cat := gen.TypeRegCategory(value.Type)
		posReg := paramRegs.iterBackward(cat)

		if !value.Storage.IsReg() {
			debugf("call param #%d: %s %s <- %s", i, cat, posReg, value)
			code.opMove(posReg, value, preserveFlags)
		}
	}

	for i := range code.vars {
		if v := &code.vars[i]; v.cache.Storage == values.VarReg {
			debugf("forget register variable #%d", i)
			// reg was already stored and freed
			v.resetCache()
		}
	}

	// account for the return address
	if n := code.stackOffset + gen.WordSize; n > code.maxStackOffset {
		code.maxStackOffset = n
	}

	if sig.Result != types.Void {
		code.pushResultRegOperand(sig.Result)
	}

	return
}

func genCurrentMemory(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	r.readVaruint1() // reserved

	code.opStabilizeOperandStack()
	result := mach.OpCurrentMemory(code)
	code.pushOperand(result)
	return
}

func genDrop(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.Discard(code.popOperand())
	return
}

func genGetGlobal(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	globalIndex := r.readVaruint32()
	if globalIndex >= uint32(len(code.globals)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := code.globals[globalIndex]
	offset := code.globalOffset(globalIndex)

	code.opStabilizeOperandStack()
	result := mach.OpGetGlobal(code, global.t, offset)
	code.pushOperand(result)
	return
}

func genGetLocal(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	localIndex := r.readVaruint32()
	if localIndex >= uint32(len(code.vars)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, localIndex))
	}

	code.pushVarOperand(int32(localIndex))
	return
}

func genGrowMemory(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	r.readVaruint1() // reserved

	x := code.opMaterializeOperand(code.popOperand())
	if x.Type != types.I32 {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	code.opStabilizeOperandStack()
	result := mach.OpGrowMemory(code, x)
	code.pushOperand(result)
	return
}

func genIf(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	t := types.InlineSignatureByEncoding(r.readVaruint7())

	code.pushBranchTarget(t, false) // end
	var afterThen links.L

	cond := code.popOperand()
	if cond.Type != types.I32 {
		panic(fmt.Errorf("if condition has wrong type: %s", cond.Type))
	}

	code.opSaveTemporaryOperands()
	code.opInitVars()
	code.opStoreVars(false)
	code.opBranchIf(cond, false, &afterThen)

	thenDeadend, haveElse := code.genThenOps(r)

	if !haveElse && t != types.Void {
		panic(errors.New("if without else has a value type"))
	}

	if !thenDeadend {
		if t != types.Void {
			value := code.popOperand()
			if value.Type != t {
				panic(fmt.Errorf("%s value operand has type %s, but target expects %s", op, value.Type, t))
			}
			code.opMove(mach.ResultReg(), value, false)
		}

		if haveElse {
			code.opSaveTemporaryOperands()
			code.opStoreVars(true)
			code.opBranch(&code.getBranchTarget(0).label) // end
		}
	}

	code.opLabel(&afterThen)
	mach.UpdateBranches(code, &afterThen)

	if haveElse {
		deadend = code.genOps(r)

		if t != types.Void && !deadend {
			value := code.popOperand()
			if value.Type != t {
				panic(fmt.Errorf("%s value operand has type %s, but target expects %s", op, value.Type, t))
			}
			code.opMove(mach.ResultReg(), value, false)
		}
	}

	end := code.popBranchTarget()
	if end.Live() { // includes thenDeadend information
		deadend = false
	}
	if !deadend {
		code.opLabel(end)
		mach.UpdateBranches(code, end)
	}

	if t != types.Void {
		code.pushResultRegOperand(t)
	}
	return
}

func skipIf(r reader, op opcode) {
	r.readVaruint7() // inline signature type
	if haveElse := skipThenOps(r); haveElse {
		skipOps(r)
	}
}

func genLoop(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	inlineSignatureType := r.readVaruint7()

	code.pushBranchTarget(types.Void, false) // begin
	code.opLabel(&code.getBranchTarget(0).label)

	savedMinBlockOperand := code.minBlockOperand
	code.minBlockOperand = len(code.operands)

	deadend = code.genOps(r)

	if deadend {
		for len(code.operands) > code.minBlockOperand {
			x := code.popOperand()
			debugf("discarding operand at end of %s due to deadend: %s", op, x)
			code.Discard(x)
		}
	} else {
		need := code.minBlockOperand
		if inlineSignatureType != 0 {
			need++ // result remains on stack
		}
		if len(code.operands) > need { // let the next guy deal with missing operands
			panic(fmt.Errorf("operands remain on stack after %s", op))
		}
	}

	code.minBlockOperand = savedMinBlockOperand

	begin := code.popBranchTarget()
	mach.UpdateBranches(code, begin)
	return
}

func skipLoop(r reader, op opcode) {
	r.readVaruint7() // inline signature type
	skipOps(r)
}

func genNop(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	return
}

func genReturn(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	if code.resultType != types.Void {
		result := code.popOperand()
		if result.Type != code.resultType {
			panic(fmt.Errorf("%s value operand type is %s, but function result type is %s", op, result.Type, code.resultType))
		}
		code.opMove(mach.ResultReg(), result, false)
	}

	mach.OpAddImmToStackPtr(code, code.stackOffset)
	mach.OpReturn(code)
	deadend = true
	return
}

func genSelect(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	cond := code.opPreloadOperand(code.popOperand())
	if cond.Type != types.I32 {
		panic(fmt.Errorf("%s: condition operand has wrong type: %s", op, cond.Type))
	}

	right := code.opMaterializeOperand(code.popOperand())
	left := code.opMaterializeOperand(code.popOperand())
	if left.Type != right.Type {
		panic(fmt.Errorf("%s: operands have inconsistent types: %s, %s", op, left.Type, right.Type))
	}

	result := mach.OpSelect(code, left, right, cond)
	code.pushOperand(result)
	return
}

func genSetGlobal(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	globalIndex := r.readVaruint32()
	if globalIndex >= uint32(len(code.globals)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := code.globals[globalIndex]
	if !global.mutable {
		panic(fmt.Errorf("%s: global %d is immutable", op, globalIndex))
	}

	offset := code.globalOffset(globalIndex)

	x := code.opMaterializeOperand(code.popOperand())
	if x.Type != global.t {
		panic(fmt.Errorf("%s operand type is %s, but type of global %d is %s", op, x.Type, globalIndex, global.t))
	}

	mach.OpSetGlobal(code, offset, x)
	return
}

func genSetLocal(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	localIndex := r.readVaruint32()
	if localIndex >= uint32(len(code.vars)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, localIndex))
	}

	code.genSetLocal(op, int32(localIndex))
	return
}

func genTeeLocal(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	localIndex := r.readVaruint32()
	if localIndex >= uint32(len(code.vars)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, localIndex))
	}

	code.genSetLocal(op, int32(localIndex))
	code.pushVarOperand(int32(localIndex))
	return
}

func (code *funcCoder) genSetLocal(op opcode, index int32) {
	debugf("setting variable #%d", index)

	v := &code.vars[index]
	t := v.cache.Type

	newValue := code.popOperand()
	if newValue.Type != t {
		panic(fmt.Errorf("%s %s variable #%d with wrong operand type: %s", op, t, index, newValue.Type))
	}

	switch newValue.Storage {
	case values.Imm:
		if v.cache.Storage == values.Imm && newValue.ImmValue() == v.cache.ImmValue() {
			return // nop
		}

	case values.VarReference:
		if newValue.VarIndex() == index {
			return // nop
		}
	}

	debugf("variable reference count: %d", v.refCount)

	if v.refCount > 0 {
		// detach all references by copying to temp regs or spilling to stack

		switch v.cache.Storage {
		case values.Nowhere, values.VarReg:
			var spillUntil int

			for i := len(code.operands) - 1; i >= 0; i-- {
				x := code.operands[i]
				if x.Storage == values.VarReference && x.VarIndex() == index {
					reg, ok := code.TryAllocReg(t)
					if !ok {
						spillUntil = i
						goto spill
					}

					zeroExt := code.opMove(reg, x, true) // TODO: avoid multiple loads
					code.operands[i] = values.TempRegOperand(t, reg, zeroExt)

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

		spill:
			code.opInitVars()

			for i := 0; i <= spillUntil; i++ {
				x := code.operands[i]
				if x.Storage == values.VarReference && x.VarIndex() == index {
					code.opPush(x) // TODO: avoid multiple loads
					code.operands[i] = values.StackOperand(t)

					v.refCount--
					if v.refCount == 0 {
						goto done
					}
					if v.refCount < 0 {
						panic("inconsistent variable reference count")
					}
				}
			}
		}

	done:
		if v.refCount != 0 {
			panic("could not find all variable references")
		}
	}

	oldCache := v.cache

	debugf("old variable cache: %s", oldCache)

	switch {
	case newValue.Storage == values.Imm:
		v.cache = newValue
		v.dirty = true

	case newValue.Storage.IsVarOrStackOrConditionFlags():
		var reg regs.R
		var ok bool

		if oldCache.Storage == values.VarReg {
			reg = oldCache.Reg()
			ok = true
			oldCache.Storage = values.Nowhere // reusing cache register, don't free it
		} else {
			reg, ok = code.opTryAllocVarReg(t)
		}

		if ok {
			zeroExt := code.opMove(reg, newValue, false)
			v.cache = values.VarRegOperand(t, index, reg, zeroExt)
			v.dirty = true
		} else {
			// spill to stack
			code.opStoreVar(index, newValue)
			v.cache = values.NoOperand(t)
			v.dirty = false
		}

	case newValue.Storage == values.TempReg:
		var reg regs.R
		var zeroExt bool
		var ok bool

		if valueReg := newValue.Reg(); code.RegAllocated(t, valueReg) {
			// repurposing the register which already contains the value
			reg = valueReg
			zeroExt = newValue.RegZeroExt()
			ok = true
		} else {
			// can't keep the transient register which contains the value
			if oldCache.Storage == values.VarReg {
				reg = oldCache.Reg()
				ok = true
				oldCache.Storage = values.Nowhere // reusing cache register, don't free it
			} else {
				reg, ok = code.opTryAllocVarReg(t)
			}

			if ok {
				// we got a register for the value
				zeroExt = code.opMove(reg, newValue, false)
			}
		}

		if ok {
			v.cache = values.VarRegOperand(t, index, reg, zeroExt)
			v.dirty = true
		} else {
			code.opStoreVar(index, newValue)
			v.cache = values.NoOperand(t)
			v.dirty = false
		}

	default:
		panic(newValue)
	}

	if oldCache.Storage == values.VarReg {
		code.FreeReg(t, oldCache.Reg())
	}
}

func genUnreachable(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	code.OpTrapCall(traps.Unreachable)
	deadend = true
	return
}

func skipMemoryImmediate(r reader, op opcode) {
	r.readVaruint32() // flags
	r.readVaruint32() // offset
}

func skipUint32(r reader, op opcode)    { r.readUint32() }
func skipUint64(r reader, op opcode)    { r.readUint64() }
func skipVarint32(r reader, op opcode)  { r.readVarint32() }
func skipVarint64(r reader, op opcode)  { r.readVarint64() }
func skipVaruint1(r reader, op opcode)  { r.readVaruint1() }
func skipVaruint32(r reader, op opcode) { r.readVaruint32() }
func skipVaruint64(r reader, op opcode) { r.readVaruint64() }
func skipNothing(r reader, op opcode)   {}

func badGen(code *funcCoder, r reader, op opcode, info opInfo) (deadend bool) {
	badOp(op)
	return
}

func badSkip(r reader, op opcode) {
	badOp(op)
}

func badOp(op opcode) {
	if s := opcodeStrings[op]; s != "" {
		panic(fmt.Errorf("unexpected opcode: %s", s))
	} else {
		panic(fmt.Errorf("invalid opcode: 0x%02x", byte(op)))
	}
}

func (code *funcCoder) opAllocReg(t types.T) (reg regs.R) {
	reg, ok := code.TryAllocReg(t)
	if !ok {
		reg = code.opStealReg(t)
	}
	return
}

func (code *funcCoder) opTryAllocVarReg(t types.T) (reg regs.R, ok bool) {
	reg, ok = code.TryAllocReg(t)
	if !ok {
		reg, ok = code.opTryStealVarReg(t)
	}
	return
}

func (code *funcCoder) opStackCheck() {
	if code.stackCheckAddr == 0 {
		debugf("stack check")
		code.stackCheckAddr = mach.OpTrapIfStackExhausted(code)
	}
}

func (code *funcCoder) opReserveStack(offset int32) {
	code.opStackCheck()

	code.stackOffset += offset
	if code.stackOffset > code.maxStackOffset {
		code.maxStackOffset = code.stackOffset
	}

	debugf("stack offset: %d", code.stackOffset)
}

func (code *funcCoder) opAdvanceStackPtr(offset int32) {
	code.opReserveStack(offset)
	mach.OpAddImmToStackPtr(code, -offset)
}

func (code *funcCoder) opBackoffStackPtr(offset int32) {
	mach.OpAddImmToStackPtr(code, offset)
	code.stackOffset -= offset

	debugf("stack offset: %d", code.stackOffset)
}

func (code *funcCoder) opPush(x values.Operand) {
	x = code.effectiveOperand(x)
	code.opReserveStack(gen.WordSize)
	mach.OpPush(code, x)
}

func (code *funcCoder) opInitVars() {
	var nothing values.Operand
	code.opInitVarsUntil(int32(len(code.vars)), nothing)
}

func (code *funcCoder) opInitVarsUntil(lastIndex int32, lastValue values.Operand) {
	for i := code.numInitedVars; i <= lastIndex && i < int32(len(code.vars)); i++ {
		v := &code.vars[i]
		x := v.cache
		if x.Storage == values.Nowhere {
			panic("variable without cached value during locals initialization")
		}
		if !v.dirty {
			panic("variable not dirty during locals initialization")
		}

		if i == lastIndex {
			x = lastValue
		}

		// float 0 has same bit pattern as int 0
		if x.Storage == values.Imm && x.ImmValue() == 0 {
			x = values.ImmOperand(types.I64, 0)
		}

		debugf("initializing variable %d/%d (%s) <- %s", i+1, len(code.vars), v.cache.Type, x)

		code.opPush(x)
		v.dirty = false

		code.numInitedVars++
	}
}

func (code *funcCoder) opBranch(l *links.L) {
	retAddr := mach.OpBranch(code, l.Addr)
	code.branchSites(l, retAddr)
}

func (code *funcCoder) opBranchIf(x values.Operand, yes bool, l *links.L) {
	x = code.effectiveOperand(x)
	retAddrs := mach.OpBranchIf(code, x, yes, l.Addr)
	code.branchSites(l, retAddrs...)
}

// func (code *funcCoder) opBranchIfEqualImm32(reg regs.R, value int, l *links.L) {
// 	site := mach.OpBranchIfEqualImm32(code, reg, value, l.Addr)
// 	code.branchSites(l, site)
// }

func (code *funcCoder) opBranchIfOutOfBounds(indexReg regs.R, upperBound int32, l *links.L) {
	site := mach.OpBranchIfOutOfBounds(code, indexReg, upperBound, l.Addr)
	code.branchSites(l, site)
}

func (code *funcCoder) opCall(l *links.L) {
	retAddr := mach.OpCall(code, l.Addr)
	code.mapCallAddr(retAddr)
	if l.Addr == 0 {
		l.AddSite(retAddr)
	}
}

// OpTrapCall generates exactly one call instruction.  (Update mach
// implementations if that ever changes.)
func (code *funcCoder) OpTrapCall(id traps.Id) {
	t := &code.trapTrampolines[id]
	t.stackOffset = code.stackOffset
	t.link.Addr = code.Len()
	code.opCall(&code.trapLinks[id])
}

// opMove must not allocate registers.
func (code *funcCoder) opMove(target regs.R, x values.Operand, preserveFlags bool) (zeroExt bool) {
	x = code.effectiveOperand(x)
	return mach.OpMove(code, target, x, preserveFlags)
}

func (code *funcCoder) opMaterializeOperand(x values.Operand) values.Operand {
	if x.Storage == values.ConditionFlags {
		reg := code.opAllocReg(x.Type)
		zeroExt := code.opMove(reg, x, false)
		return values.TempRegOperand(x.Type, reg, zeroExt)
	} else {
		return code.opPreloadOperand(x) // XXX: should this be effectiveOperand?
	}
}

func (code *funcCoder) opPreloadOperand(x values.Operand) values.Operand {
	x = code.effectiveOperand(x)

	switch x.Storage {
	case values.VarMem:
		index := x.VarIndex()
		v := &code.vars[index]

		if reg, ok := code.opTryAllocVarReg(x.Type); ok {
			zeroExt := code.opMove(reg, x, true)
			x = values.VarRegOperand(x.Type, index, reg, zeroExt).WithBounds(x.Bounds)
			v.cache = x
			v.dirty = false
		}

	case values.Stack:
		reg := code.opAllocReg(x.Type)
		zeroExt := code.opMove(reg, x, true)
		x = values.TempRegOperand(x.Type, reg, zeroExt)
	}

	return x
}

func (code *funcCoder) pushImmOperand(t types.T, bits uint64) {
	x := values.ImmOperand(t, bits)
	debugf("push operand: %s", x)
	code.operands = append(code.operands, x)
}

func (code *funcCoder) pushResultRegOperand(t types.T) {
	x := values.TempRegOperand(t, mach.ResultReg(), false)
	debugf("push operand: %s", x)
	code.operands = append(code.operands, x)
}

func (code *funcCoder) pushVarOperand(index int32) {
	v := &code.vars[index]
	x := v.cache

	switch v.cache.Storage {
	case values.Nowhere, values.VarReg: // TODO: nowhere -> ver reference without index?
		if v.refCount > len(code.operands) {
			panic(x)
		}
		v.refCount++

		x = values.VarReferenceOperand(x.Type, index)
	}

	debugf("push operand: %s", x)
	code.operands = append(code.operands, x)
}

func (code *funcCoder) pushOperand(x values.Operand) {
	if x.Storage.IsVar() {
		index := x.VarIndex()

		v := &code.vars[index]
		if v.refCount > len(code.operands) {
			panic(x)
		}
		v.refCount++

		x = values.VarReferenceOperand(x.Type, index)
	}

	debugf("push operand: %s", x)
	code.operands = append(code.operands, x)
}

func (code *funcCoder) opStabilizeOperandStack() {
	for i := code.numStableOperands; i < len(code.operands); i++ {
		x := code.operands[i]

		switch x.Storage {
		case values.TempReg:
			if code.RegAllocated(x.Type, x.Reg()) {
				continue
			}
			// do it

		case values.ConditionFlags:
			// do it

		default:
			continue
		}

		debugf("stabilizing operand: %v", x)

		reg := code.opAllocReg(x.Type)
		zeroExt := code.opMove(reg, x, false)
		code.operands[i] = values.TempRegOperand(x.Type, reg, zeroExt)
	}

	code.numStableOperands = len(code.operands)
}

func (code *funcCoder) popOperand() (x values.Operand) {
	return code.popOperands(1)[0]
}

func (code *funcCoder) popOperands(n int) (xs []values.Operand) {
	i := len(code.operands) - n
	if i < code.minBlockOperand {
		panic(errors.New("operand stack of block is empty"))
	}

	xs = code.operands[i:]
	code.operands = code.operands[:i]

	if code.numStableOperands > i {
		code.numStableOperands = i

		if code.numPersistentOperands > i {
			code.numPersistentOperands = i
		}
	}

	for _, x := range xs {
		if x.Storage == values.VarReference {
			v := &code.vars[x.VarIndex()]
			v.refCount--
			if v.refCount < 0 {
				panic(x)
			}
		}
	}

	for i, x := range xs {
		debugf("pop operand %d/%d: %s", i+1, len(xs), x)
	}

	return
}

// opStealReg doesn't change the allocation state of the register.
func (code *funcCoder) opStealReg(needType types.T) (reg regs.R) {
	debugf("steal %s register", needType)

	reg, ok := code.opTryStealVarReg(needType)
	if ok {
		return
	}

	pushed := false

	for i := code.numPersistentOperands; i < len(code.operands); i++ {
		x := code.operands[i]

		switch x.Storage {
		case values.Imm, values.VarReference:

		case values.TempReg:
			reg = x.Reg()

			code.opInitVars()
			code.opPush(x)
			code.AllocSpecificReg(x.Type, reg)
			code.operands[i] = values.StackOperand(x.Type)
			pushed = true

			if x.Type.Category() == needType.Category() {
				if n := i + 1; code.numStableOperands < n {
					code.numStableOperands = n
				}
				return
			}

		case values.ConditionFlags:
			code.opInitVars()
			code.opPush(x)
			code.operands[i] = values.StackOperand(x.Type)
			pushed = true

		case values.Stack:
			if pushed {
				panic(x)
			}

		default:
			panic(x)
		}
	}

	panic("no registers to steal")
}

// opTryStealVarReg doesn't change the allocation state of the register.
func (code *funcCoder) opTryStealVarReg(needType types.T) (reg regs.R, ok bool) {
	debugf("try steal %s variable register", needType)

	code.opInitVars()

	var bestIndex = -1
	var bestRefCount int

	for i, v := range code.vars {
		if v.cache.Storage == values.VarReg && v.cache.Type.Category() == needType.Category() {
			if bestIndex < 0 || v.refCount < bestRefCount {
				bestIndex = i
				bestRefCount = v.refCount

				if bestRefCount == 0 {
					goto found
				}
			}
		}
	}

	if bestIndex < 0 {
		return
	}

found:
	v := &code.vars[bestIndex]
	reg = v.cache.Reg()
	if v.dirty {
		index := int32(bestIndex)
		code.opStoreVar(index, values.VarReferenceOperand(v.cache.Type, index)) // XXX: this is ugly
	}
	v.resetCache()
	ok = true
	return
}

func (code *funcCoder) opSaveTemporaryOperands() {
	debugf("save temporary register operands")

	for i := code.numPersistentOperands; i < len(code.operands); i++ {
		if x := code.operands[i]; x.Storage.IsTempRegOrConditionFlags() {
			code.opInitVars()
			code.opPush(x)
			code.operands[i] = values.StackOperand(x.Type)
		}
	}

	code.numPersistentOperands = len(code.operands)
	code.numStableOperands = len(code.operands)
}

func (code *funcCoder) opStoreVars(forget bool) {
	if forget {
		debugf("store and forget variables")
	} else {
		debugf("store but remember variables")
	}

	for i := range code.vars {
		v := &code.vars[i]

		if v.dirty {
			index := int32(i)
			code.opStoreVar(index, values.VarReferenceOperand(v.cache.Type, index)) // XXX: this is ugly
			v.dirty = false
		}

		if forget {
			if v.cache.Storage == values.VarReg {
				code.FreeReg(v.cache.Type, v.cache.Reg())
			}
			v.resetCache()
		}
	}
}

func (code *funcCoder) opStoreRegVars() {
	debugf("store but remember register variables")

	for i := range code.vars {
		if v := &code.vars[i]; v.cache.Storage == values.VarReg && v.dirty {
			index := int32(i)
			code.opStoreVar(index, values.VarReferenceOperand(v.cache.Type, index)) // XXX: this is ugly
			v.dirty = false
		}
	}
}

func (code *funcCoder) opStoreVar(index int32, x values.Operand) {
	x = code.effectiveOperand(x)

	debugf("store variable #%d <- %s", index, x)

	if index >= code.numInitedVars {
		code.opInitVarsUntil(index, x)
	} else {
		offset := code.effectiveVarStackOffset(index)
		mach.OpStoreStack(code, offset, x)
	}
}

func (code *funcCoder) opLabel(l *links.L) {
	code.opSaveTemporaryOperands()
	code.opStoreVars(true)
	l.Addr = code.Len()

	debugf("label")
}
