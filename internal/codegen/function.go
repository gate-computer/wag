// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/regalloc"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/typeutil"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/meta"
	"github.com/tsavola/wag/trap"
)

const (
	MaxImportParams    = gen.StackReserve/gen.WordSize - 2
	MaxFuncParams      = 255   // index+1 must fit in uint8
	MaxFuncVars        = 8191  // index must fit in uint16; TODO
	MaxEntryParams     = 8     // param registers on x86-64
	MaxBranchTableSize = 32768 // TODO
)

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

type function struct {
	*Module

	resultType abi.Type

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

	trapTrampolines [trap.NumTraps]trampoline
}

func (f *function) AllocSpecificReg(t abi.Type, reg regs.R)  { allocSpecificReg(f, t, reg) }
func (f *function) Bytes() []byte                            { return f.Text.Bytes() }
func (f *function) Consumed(x values.Operand)                { consumed(f, x) }
func (f *function) Discard(x values.Operand)                 { discard(f, x) }
func (f *function) Extend(n int) []byte                      { return f.Text.Extend(n) }
func (f *function) FreeReg(t abi.Type, reg regs.R)           { freeReg(f, t, reg) }
func (f *function) MinMemorySize() int                       { return f.MemoryLimitValues.Initial }
func (f *function) OpTrapCall(id trap.Id)                    { opTrapCall(f, id) }
func (f *function) Pos() int32                               { return f.Text.Pos() }
func (f *function) PutByte(b byte)                           { f.Text.PutByte(b) }
func (f *function) PutBytes(b []byte)                        { f.Text.PutBytes(b) }
func (f *function) RODataAddr() int32                        { return f.Module.RODataAddr }
func (f *function) RegAllocated(t abi.Type, reg regs.R) bool { return regAllocated(f, t, reg) }
func (f *function) TrapTrampolineAddr(id trap.Id) int32      { return trapTrampolineAddr(f, id) }
func (f *function) TryAllocReg(t abi.Type) (regs.R, bool)    { return tryAllocReg(f, t) }

func tryAllocReg(f *function, t abi.Type) (reg regs.R, ok bool) {
	return f.Regs.Alloc(gen.TypeRegCategory(t))
}

func allocSpecificReg(f *function, t abi.Type, reg regs.R) {
	f.Regs.AllocSpecific(gen.TypeRegCategory(t), reg)
}

func freeReg(f *function, t abi.Type, reg regs.R) {
	f.Regs.Free(gen.TypeRegCategory(t), reg)
}

// regAllocated indicates if we can hang onto a register returned by mach ops.
func regAllocated(f *function, t abi.Type, reg regs.R) bool {
	return f.Regs.Allocated(gen.TypeRegCategory(t), reg)
}

func consumed(f *function, x values.Operand) {
	switch x.Storage {
	case values.TempReg:
		freeReg(f, x.Type, x.Reg())

	case values.Stack:
		f.stackOffset -= gen.WordSize

		debugf("stack offset: %d", f.stackOffset)
	}
}

func discard(f *function, x values.Operand) {
	switch x.Storage {
	case values.TempReg:
		freeReg(f, x.Type, x.Reg())

	case values.Stack:
		opBackoffStackPtr(f, gen.WordSize)
	}
}

func effectiveOperand(f *function, x values.Operand) values.Operand {
	if x.Storage == values.VarReference {
		index := x.VarIndex()
		v := f.vars[index]

		if v.cache.Storage == values.Nowhere {
			x = values.VarMemOperand(x.Type, index, effectiveVarStackOffset(f, index))
		} else {
			x = v.cache
		}

		if i := len(v.boundsStack) - 1; i >= 0 {
			x = x.WithBounds(v.boundsStack[i])
		}
	}

	return x
}

func effectiveVarStackOffset(f *function, index int32) (offset int32) {
	if index < f.numStackParams {
		paramPos := f.numStackParams - index - 1
		// account for the function return address
		offset = f.stackOffset + gen.WordSize + paramPos*gen.WordSize
	} else {
		regParamIndex := index - f.numStackParams
		offset = f.stackOffset - (regParamIndex+1)*gen.WordSize
	}

	if offset < 0 {
		panic("effective stack offset is negative")
	}
	return
}

func updateMemoryIndex(f *function, index values.Operand, offset uint32, oper uint16) {
	if index.Storage.IsVar() {
		v := &f.vars[index.VarIndex()]

		if v.cache.Storage == values.VarReg && !v.cache.RegZeroExt() {
			// LoadOp and StoreOp make sure that index gets zero-extended if it's a VarReg operand
			v.cache = values.VarRegOperand(v.cache.Type, v.cache.VarIndex(), v.cache.Reg(), true)
		}

		size := oper >> 8
		upper := uint64(offset) + uint64(size)

		if upper <= 0x80000000 {
			// enlarge the stack

			level := boundsStackLevel(f)

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

			if uint32(upper) > bounds.Upper {
				bounds.Upper = uint32(upper)
			}

			debugf("variable #%d upper bound set to %d", index.VarIndex(), bounds.Upper)
		}
	}
}

func genFunction(f *function, load loader.L, funcIndex int) {
	sigIndex := f.FuncSigs[funcIndex]
	sig := f.Sigs[sigIndex]

	if debug {
		debugf("function %d %s", funcIndex-len(f.ImportFuncs), sig)
		debugDepth++
	}

	load.Varuint32() // body size

	isa.AlignFunc(f)
	addr := f.Pos()
	f.FuncLinks[funcIndex].Addr = addr
	f.Mapper.PutFuncAddr(meta.TextAddr(addr))
	isa.OpEnterFunc(f)

	f.resultType = sig.Result

	f.vars = make([]varState, len(sig.Args))

	var paramRegs regalloc.Iterator
	f.numStackParams = paramRegs.Init(isa.ParamRegs(), sig.Args)
	f.numInitedVars = f.numStackParams // they're already there

	for i := 0; i < int(f.numStackParams); i++ {
		f.vars[i].cache = values.NoOperand(sig.Args[i])
	}

	for i := f.numStackParams; i < int32(len(sig.Args)); i++ {
		t := sig.Args[i]
		cat := gen.TypeRegCategory(t)
		reg := paramRegs.IterForward(cat)
		f.Regs.AllocSpecific(cat, reg)
		f.vars[i] = varState{
			cache: values.VarRegOperand(t, i, reg, false),
			dirty: true,
		}
	}

	for range load.Count() {
		params := load.Count()
		if uint64(len(f.vars))+uint64(len(params)) >= MaxFuncVars {
			panic(fmt.Errorf("function #%d has too many variables: %d params, %d locals", funcIndex, len(params), len(f.vars)))
		}

		t := typeutil.ValueTypeByEncoding(load.Varint7())

		for range params {
			f.vars = append(f.vars, varState{
				cache: values.ImmOperand(t, 0),
				dirty: true,
			})
		}
	}

	pushBranchTarget(f, f.resultType, true)

	deadend := genOps(f, load)

	if f.minBlockOperand != 0 {
		panic("minimum operand index is not zero at end of function")
	}

	if deadend {
		for len(f.operands) > 0 {
			x := popOperand(f)
			debugf("discarding operand at end of function due to deadend: %s", x)
			discard(f, x)
		}
	} else if f.resultType != abi.Void {
		result := popOperand(f)
		if result.Type != f.resultType {
			panic(fmt.Errorf("function result operand type is %s, but function result type is %s", result.Type, f.resultType))
		}
		opMove(f, regs.Result, result, false)
	}

	if end := popBranchTarget(f); end.Live() {
		opLabel(f, end)
		isa.UpdateBranches(f.Bytes(), end)
		deadend = false
	}

	if !deadend {
		opBackoffStackPtr(f, f.stackOffset)
		isa.OpReturn(f)
	}

	if len(f.operands) != 0 {
		debugf("operand stack: %v", f.operands)
		panic(errors.New("operand stack is not empty at end of function"))
	}

	if len(f.branchTargets) != 0 {
		panic("branch target stack is not empty at end of function")
	}

	for i := range f.vars {
		v := f.vars[i]
		if v.cache.Storage == values.VarReg {
			freeReg(f, v.cache.Type, v.cache.Reg())
		}
	}

	f.Regs.AssertNoneAllocated()

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

	if f.stackCheckAddr != 0 {
		isa.UpdateStackCheck(f.Bytes(), f.stackCheckAddr, f.maxStackOffset)
	}

	roDataBuf := f.ROData.Bytes()

	for _, table := range f.branchTables {
		buf := roDataBuf[table.roDataAddr:]
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

func opAllocReg(f *function, t abi.Type) (reg regs.R) {
	reg, ok := tryAllocReg(f, t)
	if !ok {
		reg = opStealReg(f, t)
	}
	return
}

func opTryAllocVarReg(f *function, t abi.Type) (reg regs.R, ok bool) {
	reg, ok = tryAllocReg(f, t)
	if !ok {
		reg, ok = opTryStealVarReg(f, t)
	}
	return
}

func opStackCheck(f *function) {
	if f.stackCheckAddr == 0 {
		debugf("stack check")
		f.stackCheckAddr = isa.OpTrapIfStackExhausted(f)
	}
}

func opReserveStack(f *function, offset int32) {
	opStackCheck(f)

	f.stackOffset += offset
	if f.stackOffset > f.maxStackOffset {
		f.maxStackOffset = f.stackOffset
	}

	debugf("stack offset: %d", f.stackOffset)
}

func opAdvanceStackPtr(f *function, offset int32) {
	opReserveStack(f, offset)
	isa.OpAddImmToStackPtr(f, -offset)
}

func opBackoffStackPtr(f *function, offset int32) {
	isa.OpAddImmToStackPtr(f, offset)
	f.stackOffset -= offset

	debugf("stack offset: %d", f.stackOffset)
}

func opPush(f *function, x values.Operand) {
	x = effectiveOperand(f, x)
	opReserveStack(f, gen.WordSize)
	isa.OpPush(f, x)
}

func opInitVars(f *function) {
	var nothing values.Operand
	opInitVarsUntil(f, int32(len(f.vars)), nothing)
}

func opInitVarsUntil(f *function, lastIndex int32, lastValue values.Operand) {
	for i := f.numInitedVars; i <= lastIndex && i < int32(len(f.vars)); i++ {
		v := &f.vars[i]
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
			x = values.ImmOperand(abi.I64, 0)
		}

		debugf("initializing variable %d/%d (%s) <- %s", i+1, len(f.vars), v.cache.Type, x)

		opPush(f, x)
		v.dirty = false

		f.numInitedVars++
	}
}

// opMove must not allocate registers.
func opMove(f *function, target regs.R, x values.Operand, preserveFlags bool) (zeroExt bool) {
	x = effectiveOperand(f, x)
	return isa.OpMove(f, target, x, preserveFlags)
}

func opMaterializeOperand(f *function, x values.Operand) values.Operand {
	if x.Storage == values.ConditionFlags {
		reg := opAllocReg(f, x.Type)
		zeroExt := opMove(f, reg, x, false)
		return values.TempRegOperand(x.Type, reg, zeroExt)
	} else {
		return opPreloadOperand(f, x) // XXX: should this be effectiveOperand?
	}
}

func opPreloadOperand(f *function, x values.Operand) values.Operand {
	x = effectiveOperand(f, x)

	switch x.Storage {
	case values.VarMem:
		index := x.VarIndex()
		v := &f.vars[index]

		if reg, ok := opTryAllocVarReg(f, x.Type); ok {
			zeroExt := opMove(f, reg, x, true)
			x = values.VarRegOperand(x.Type, index, reg, zeroExt).WithBounds(x.Bounds)
			v.cache = x
			v.dirty = false
		}

	case values.Stack:
		reg := opAllocReg(f, x.Type)
		zeroExt := opMove(f, reg, x, true)
		x = values.TempRegOperand(x.Type, reg, zeroExt)
	}

	return x
}

func pushImmOperand(f *function, t abi.Type, bits uint64) {
	x := values.ImmOperand(t, bits)
	debugf("push operand: %s", x)
	f.operands = append(f.operands, x)
}

func pushResultRegOperand(f *function, t abi.Type) {
	x := values.TempRegOperand(t, regs.Result, false)
	debugf("push operand: %s", x)
	f.operands = append(f.operands, x)
}

func pushVarOperand(f *function, index int32) {
	v := &f.vars[index]
	x := v.cache

	switch v.cache.Storage {
	case values.Nowhere, values.VarReg: // TODO: nowhere -> ver reference without index?
		v.refCount++
		x = values.VarReferenceOperand(x.Type, index)
	}

	debugf("push operand: %s", x)
	f.operands = append(f.operands, x)
}

func pushOperand(f *function, x values.Operand) {
	if x.Storage.IsVar() {
		index := x.VarIndex()
		f.vars[index].refCount++
		x = values.VarReferenceOperand(x.Type, index)
	}

	debugf("push operand: %s", x)
	f.operands = append(f.operands, x)
}

func opStabilizeOperandStack(f *function) {
	for i := f.numStableOperands; i < len(f.operands); i++ {
		x := f.operands[i]

		switch x.Storage {
		case values.TempReg:
			if regAllocated(f, x.Type, x.Reg()) {
				continue
			}
			// do it

		case values.ConditionFlags:
			// do it

		default:
			continue
		}

		debugf("stabilizing operand: %v", x)

		reg := opAllocReg(f, x.Type)
		zeroExt := opMove(f, reg, x, false)
		f.operands[i] = values.TempRegOperand(x.Type, reg, zeroExt)
	}

	f.numStableOperands = len(f.operands)
}

func popOperand(f *function) (x values.Operand) {
	return popOperands(f, 1)[0]
}

func popOperands(f *function, n int) (xs []values.Operand) {
	i := len(f.operands) - n
	if i < f.minBlockOperand {
		panic(errors.New("operand stack of block is empty"))
	}

	xs = f.operands[i:]
	f.operands = f.operands[:i]

	if f.numStableOperands > i {
		f.numStableOperands = i

		if f.numPersistentOperands > i {
			f.numPersistentOperands = i
		}
	}

	for _, x := range xs {
		if x.Storage == values.VarReference {
			f.vars[x.VarIndex()].refCount--
		}
	}

	if debug {
		for i, x := range xs {
			debugf("pop operand %d/%d: %s", i+1, len(xs), x)
		}
	}

	return
}

// opStealReg doesn't change the allocation state of the register.
func opStealReg(f *function, needType abi.Type) (reg regs.R) {
	debugf("steal %s register", needType)

	reg, ok := opTryStealVarReg(f, needType)
	if ok {
		return
	}

	opInitVars(f)

	for i := f.numPersistentOperands; i < len(f.operands); i++ {
		x := f.operands[i]

		if x.Type.Category() == needType.Category() {
			switch x.Storage {
			case values.VarReference:
				if v := f.vars[x.VarIndex()]; v.cache.Storage == values.VarReg {
					reg = v.cache.Reg()
					ok = true
				}

			case values.TempReg:
				reg = x.Reg()
				if regAllocated(f, x.Type, reg) {
					defer allocSpecificReg(f, x.Type, reg)
					ok = true
				}
			}
		}

		switch x.Storage {
		case values.VarReference:
			f.vars[x.VarIndex()].refCount--
			fallthrough
		case values.TempReg, values.ConditionFlags:
			opPush(f, x)
			f.operands[i] = values.StackOperand(x.Type)
		}

		if ok {
			if n := i + 1; f.numStableOperands < n {
				f.numStableOperands = n
			}
			return
		}
	}

	panic("no registers to steal")
}

// opTryStealVarReg doesn't change the allocation state of the register.
func opTryStealVarReg(f *function, needType abi.Type) (reg regs.R, ok bool) {
	debugf("try steal %s variable register", needType)

	opInitVars(f)

	var bestIndex = -1
	var bestRefCount int

	for i, v := range f.vars {
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
	v := &f.vars[bestIndex]
	reg = v.cache.Reg()
	if v.dirty {
		index := int32(bestIndex)
		opStoreVar(f, index, values.VarReferenceOperand(v.cache.Type, index)) // XXX: this is ugly
	}
	v.resetCache()
	ok = true
	return
}

func opSaveTemporaryOperands(f *function) {
	debugf("save temporary register operands")

	for i := f.numPersistentOperands; i < len(f.operands); i++ {
		x := f.operands[i]

		switch {
		case x.Storage == values.VarReference:
			f.vars[x.VarIndex()].refCount--
			fallthrough
		case x.Storage.IsTempRegOrConditionFlags():
			opInitVars(f)
			opPush(f, x)
			f.operands[i] = values.StackOperand(x.Type)
		}
	}

	f.numPersistentOperands = len(f.operands)
	f.numStableOperands = len(f.operands)
}

func opStoreVars(f *function, forget bool) {
	if forget {
		debugf("store and forget variables")
	} else {
		debugf("store but remember variables")
	}

	for i := range f.vars {
		v := &f.vars[i]

		if v.dirty {
			index := int32(i)
			opStoreVar(f, index, values.VarReferenceOperand(v.cache.Type, index)) // XXX: this is ugly
			v.dirty = false
		}

		if forget {
			if v.cache.Storage == values.VarReg {
				freeReg(f, v.cache.Type, v.cache.Reg())
			}
			v.resetCache()
		}
	}
}

func opStoreRegVars(f *function) {
	debugf("store but remember register variables")

	for i := range f.vars {
		if v := &f.vars[i]; v.cache.Storage == values.VarReg && v.dirty {
			index := int32(i)
			opStoreVar(f, index, values.VarReferenceOperand(v.cache.Type, index)) // XXX: this is ugly
			v.dirty = false
		}
	}
}

func opStoreVar(f *function, index int32, x values.Operand) {
	x = effectiveOperand(f, x)

	debugf("store variable #%d <- %s", index, x)

	if index >= f.numInitedVars {
		opInitVarsUntil(f, index, x)
	} else {
		offset := effectiveVarStackOffset(f, index)
		isa.OpStoreStack(f, offset, x)
	}
}
