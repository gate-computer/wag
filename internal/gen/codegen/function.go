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
	"github.com/tsavola/wag/internal/gen/regalloc"
	"github.com/tsavola/wag/internal/gen/val"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/typeutil"
)

const (
	MaxFuncParams      = 255   // index+1 must fit in uint8
	MaxFuncVars        = 8191  // index must fit in uint16; TODO
	MaxEntryParams     = 8     // param registers on x86-64
	MaxBranchTableSize = 32768 // TODO
)

func discard(f *gen.Func, x val.Operand) {
	switch x.Storage {
	case val.TempReg:
		f.Regs.Free(x.Type, x.Reg())

	case val.Stack:
		opBackoffStackPtr(f, obj.Word)
	}
}

func effectiveOperand(f *gen.Func, x val.Operand) val.Operand {
	if x.Storage == val.VarReference {
		index := x.VarIndex()
		v := f.Vars[index]

		if v.Cache.Storage == val.Nowhere {
			x = val.VarMemOperand(x.Type, index, effectiveVarStackOffset(f, index))
		} else {
			x = v.Cache
		}

		if i := len(v.BoundsStack) - 1; i >= 0 {
			x = x.WithBounds(v.BoundsStack[i])
		}
	}

	return x
}

func effectiveVarStackOffset(f *gen.Func, index int32) (offset int32) {
	if index < f.NumStackParams {
		paramPos := f.NumStackParams - index - 1
		// account for the function return address
		offset = f.StackOffset + obj.Word + paramPos*obj.Word
	} else {
		regParamIndex := index - f.NumStackParams
		offset = f.StackOffset - (regParamIndex+1)*obj.Word
	}

	if offset < 0 {
		panic("effective stack offset is negative")
	}
	return
}

func updateMemoryIndex(f *gen.Func, index val.Operand, offset uint32, props uint16) {
	if index.Storage.IsVar() {
		v := &f.Vars[index.VarIndex()]

		if v.Cache.Storage == val.VarReg && !v.Cache.RegZeroExt() {
			// LoadOp and StoreOp make sure that index gets zero-extended if it's a VarReg operand
			v.Cache = val.VarRegOperand(v.Cache.Type, v.Cache.VarIndex(), v.Cache.Reg(), true)
		}

		size := props >> 8
		upper := uint64(offset) + uint64(size)

		if upper <= 0x80000000 {
			// enlarge the stack

			level := boundsStackLevel(f)

			currSize := len(v.BoundsStack)
			needSize := level + 1

			if currSize < needSize {
				if cap(v.BoundsStack) >= needSize {
					v.BoundsStack = v.BoundsStack[:needSize]
				} else {
					buf := make([]val.Bounds, needSize)
					copy(buf, v.BoundsStack)
					v.BoundsStack = buf
				}

				var lastValue val.Bounds
				if currSize > 0 {
					lastValue = v.BoundsStack[currSize-1]
				}

				for i := currSize; i < needSize; i++ {
					v.BoundsStack[i] = lastValue
				}
			}

			// update the bounds

			bounds := &v.BoundsStack[level]

			if uint32(upper) > bounds.Upper {
				bounds.Upper = uint32(upper)
			}

			debugf("variable #%d upper bound set to %d", index.VarIndex(), bounds.Upper)
		}
	}
}

func genFunction(m *module.M, p *gen.Prog, load loader.L, funcIndex int) {
	f := &gen.Func{
		M:    m,
		Prog: p,
		Regs: regalloc.MakeAllocator(isa.AvailRegs()),
	}

	sigIndex := f.FuncSigs[funcIndex]
	sig := f.Sigs[sigIndex]

	if debug {
		debugf("function %d %s", funcIndex-len(f.ImportFuncs), sig)
		debugDepth++
	}

	load.Varuint32() // body size

	isa.AlignFunc(m)
	addr := f.Text.Addr
	f.FuncLinks[funcIndex].Addr = addr
	f.Map.PutFuncAddr(addr)
	isa.OpEnterFunc(f)

	f.ResultType = sig.Result

	f.Vars = make([]gen.VarState, len(sig.Args))

	var paramRegs regalloc.Iterator
	f.NumStackParams = paramRegs.Init(isa.ParamRegs(), sig.Args)
	f.NumInitedVars = f.NumStackParams // they're already there

	for i := 0; i < int(f.NumStackParams); i++ {
		f.Vars[i].Cache = val.NoOperand(sig.Args[i])
	}

	for i := f.NumStackParams; i < int32(len(sig.Args)); i++ {
		t := sig.Args[i]
		reg := paramRegs.IterForward(t.Category())
		f.Regs.AllocSpecific(t, reg)
		f.Vars[i] = gen.VarState{
			Cache: val.VarRegOperand(t, i, reg, false),
			Dirty: true,
		}
	}

	for range load.Count() {
		params := load.Count()
		if uint64(len(f.Vars))+uint64(len(params)) >= MaxFuncVars {
			panic(fmt.Errorf("function #%d has too many variables: %d params, %d locals", funcIndex, len(params), len(f.Vars)))
		}

		t := typeutil.ValueTypeByEncoding(load.Varint7())

		for range params {
			f.Vars = append(f.Vars, gen.VarState{
				Cache: val.ImmOperand(t, 0),
				Dirty: true,
			})
		}
	}

	pushBranchTarget(f, f.ResultType, true)

	deadend := genOps(f, load)

	if f.MinBlockOperand != 0 {
		panic("minimum operand index is not zero at end of function")
	}

	if deadend {
		for len(f.Operands) > 0 {
			x := popOperand(f)
			debugf("discarding operand at end of function due to deadend: %s", x)
			discard(f, x)
		}
	} else if f.ResultType != abi.Void {
		result := popOperand(f)
		if result.Type != f.ResultType {
			panic(fmt.Errorf("function result operand type is %s, but function result type is %s", result.Type, f.ResultType))
		}
		opMove(f, regs.Result, result, false)
	}

	if end := popBranchTarget(f); end.Live() {
		opLabel(f, end)
		isa.UpdateBranches(f.Text.Bytes(), end)
		deadend = false
	}

	if !deadend {
		opBackoffStackPtr(f, f.StackOffset)
		isa.OpReturn(m)
	}

	if len(f.Operands) != 0 {
		debugf("operand stack: %v", f.Operands)
		panic(errors.New("operand stack is not empty at end of function"))
	}

	if len(f.BranchTargets) != 0 {
		panic("branch target stack is not empty at end of function")
	}

	for i := range f.Vars {
		v := f.Vars[i]
		if v.Cache.Storage == val.VarReg {
			f.Regs.Free(v.Cache.Type, v.Cache.Reg())
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

	if f.StackCheckAddr != 0 {
		isa.UpdateStackCheck(f.Text.Bytes(), f.StackCheckAddr, f.MaxStackOffset)
	}

	roDataBuf := f.ROData.Bytes()

	for _, table := range f.BranchTables {
		buf := roDataBuf[table.RODataAddr:]
		for _, target := range table.Targets {
			targetAddr := uint32(target.Label.FinalAddr())
			if table.CodeStackOffset < 0 {
				// common offset
				binary.LittleEndian.PutUint32(buf[:4], targetAddr)
				buf = buf[4:]
			} else {
				delta := table.CodeStackOffset - target.StackOffset
				packed := (uint64(uint32(delta)) << 32) | uint64(targetAddr)
				binary.LittleEndian.PutUint64(buf[:8], packed)
				buf = buf[8:]
			}
		}
	}

	return
}

func opAllocReg(f *gen.Func, t abi.Type) (reg regs.R) {
	reg, ok := f.Regs.Alloc(t)
	if !ok {
		reg = opStealReg(f, t)
	}
	return
}

func opTryAllocVarReg(f *gen.Func, t abi.Type) (reg regs.R, ok bool) {
	reg, ok = f.Regs.Alloc(t)
	if !ok {
		reg, ok = opTryStealVarReg(f, t)
	}
	return
}

func opStackCheck(f *gen.Func) {
	if f.StackCheckAddr == 0 {
		debugf("stack check")
		f.StackCheckAddr = isa.OpTrapIfStackExhausted(f)
	}
}

func opReserveStack(f *gen.Func, offset int32) {
	opStackCheck(f)

	f.StackOffset += offset
	if f.StackOffset > f.MaxStackOffset {
		f.MaxStackOffset = f.StackOffset
	}

	debugf("stack offset: %d", f.StackOffset)
}

func opAdvanceStackPtr(f *gen.Func, offset int32) {
	opReserveStack(f, offset)
	isa.OpAddImmToStackPtr(f.M, -offset)
}

func opBackoffStackPtr(f *gen.Func, offset int32) {
	isa.OpAddImmToStackPtr(f.M, offset)
	f.StackOffset -= offset

	debugf("stack offset: %d", f.StackOffset)
}

func opPush(f *gen.Func, x val.Operand) {
	x = effectiveOperand(f, x)
	opReserveStack(f, obj.Word)
	isa.OpPush(f, x)
}

func opInitVars(f *gen.Func) {
	var nothing val.Operand
	opInitVarsUntil(f, int32(len(f.Vars)), nothing)
}

func opInitVarsUntil(f *gen.Func, lastIndex int32, lastValue val.Operand) {
	for i := f.NumInitedVars; i <= lastIndex && i < int32(len(f.Vars)); i++ {
		v := &f.Vars[i]
		x := v.Cache
		if x.Storage == val.Nowhere {
			panic("variable without cached value during locals initialization")
		}
		if !v.Dirty {
			panic("variable not dirty during locals initialization")
		}

		if i == lastIndex {
			x = lastValue
		}

		// float 0 has same bit pattern as int 0
		if x.Storage == val.Imm && x.ImmValue() == 0 {
			x = val.ImmOperand(abi.I64, 0)
		}

		debugf("initializing variable %d/%d (%s) <- %s", i+1, len(f.Vars), v.Cache.Type, x)

		opPush(f, x)
		v.Dirty = false

		f.NumInitedVars++
	}
}

// opMove must not allocate registers.
func opMove(f *gen.Func, target regs.R, x val.Operand, preserveFlags bool) (zeroExt bool) {
	x = effectiveOperand(f, x)
	return isa.OpMove(f, target, x, preserveFlags)
}

func opMaterializeOperand(f *gen.Func, x val.Operand) val.Operand {
	if x.Storage == val.ConditionFlags {
		reg := opAllocReg(f, x.Type)
		zeroExt := opMove(f, reg, x, false)
		return val.TempRegOperand(x.Type, reg, zeroExt)
	} else {
		return opPreloadOperand(f, x) // XXX: should this be effectiveOperand?
	}
}

func opPreloadOperand(f *gen.Func, x val.Operand) val.Operand {
	x = effectiveOperand(f, x)

	switch x.Storage {
	case val.VarMem:
		index := x.VarIndex()
		v := &f.Vars[index]

		if reg, ok := opTryAllocVarReg(f, x.Type); ok {
			zeroExt := opMove(f, reg, x, true)
			x = val.VarRegOperand(x.Type, index, reg, zeroExt).WithBounds(x.Bounds)
			v.Cache = x
			v.Dirty = false
		}

	case val.Stack:
		reg := opAllocReg(f, x.Type)
		zeroExt := opMove(f, reg, x, true)
		x = val.TempRegOperand(x.Type, reg, zeroExt)
	}

	return x
}

func pushImmOperand(f *gen.Func, t abi.Type, bits uint64) {
	x := val.ImmOperand(t, bits)
	debugf("push operand: %s", x)
	f.Operands = append(f.Operands, x)
}

func pushResultRegOperand(f *gen.Func, t abi.Type) {
	x := val.TempRegOperand(t, regs.Result, false)
	debugf("push operand: %s", x)
	f.Operands = append(f.Operands, x)
}

func pushVarOperand(f *gen.Func, index int32) {
	v := &f.Vars[index]
	x := v.Cache

	switch v.Cache.Storage {
	case val.Nowhere, val.VarReg: // TODO: nowhere -> ver reference without index?
		v.RefCount++
		x = val.VarReferenceOperand(x.Type, index)
	}

	debugf("push operand: %s", x)
	f.Operands = append(f.Operands, x)
}

func pushOperand(f *gen.Func, x val.Operand) {
	if x.Storage.IsVar() {
		index := x.VarIndex()
		f.Vars[index].RefCount++
		x = val.VarReferenceOperand(x.Type, index)
	}

	debugf("push operand: %s", x)
	f.Operands = append(f.Operands, x)
}

func opStabilizeOperandStack(f *gen.Func) {
	for i := f.NumStableOperands; i < len(f.Operands); i++ {
		x := f.Operands[i]

		switch x.Storage {
		case val.TempReg:
			if f.Regs.Allocated(x.Type, x.Reg()) {
				continue
			}
			// do it

		case val.ConditionFlags:
			// do it

		default:
			continue
		}

		debugf("stabilizing operand: %v", x)

		reg := opAllocReg(f, x.Type)
		zeroExt := opMove(f, reg, x, false)
		f.Operands[i] = val.TempRegOperand(x.Type, reg, zeroExt)
	}

	f.NumStableOperands = len(f.Operands)
}

func popOperand(f *gen.Func) (x val.Operand) {
	return popOperands(f, 1)[0]
}

func popOperands(f *gen.Func, n int) (xs []val.Operand) {
	i := len(f.Operands) - n
	if i < f.MinBlockOperand {
		panic(errors.New("operand stack of block is empty"))
	}

	xs = f.Operands[i:]
	f.Operands = f.Operands[:i]

	if f.NumStableOperands > i {
		f.NumStableOperands = i

		if f.NumPersistentOperands > i {
			f.NumPersistentOperands = i
		}
	}

	for _, x := range xs {
		if x.Storage == val.VarReference {
			f.Vars[x.VarIndex()].RefCount--
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
func opStealReg(f *gen.Func, needType abi.Type) (reg regs.R) {
	debugf("steal %s register", needType)

	reg, ok := opTryStealVarReg(f, needType)
	if ok {
		return
	}

	opInitVars(f)

	for i := f.NumPersistentOperands; i < len(f.Operands); i++ {
		x := f.Operands[i]

		if x.Type.Category() == needType.Category() {
			switch x.Storage {
			case val.VarReference:
				if v := f.Vars[x.VarIndex()]; v.Cache.Storage == val.VarReg {
					reg = v.Cache.Reg()
					ok = true
				}

			case val.TempReg:
				reg = x.Reg()
				if f.Regs.Allocated(x.Type, reg) {
					defer f.Regs.AllocSpecific(x.Type, reg)
					ok = true
				}
			}
		}

		switch x.Storage {
		case val.VarReference:
			f.Vars[x.VarIndex()].RefCount--
			fallthrough
		case val.TempReg, val.ConditionFlags:
			opPush(f, x)
			f.Operands[i] = val.StackOperand(x.Type)
		}

		if ok {
			if n := i + 1; f.NumStableOperands < n {
				f.NumStableOperands = n
			}
			return
		}
	}

	panic("no registers to steal")
}

// opTryStealVarReg doesn't change the allocation state of the register.
func opTryStealVarReg(f *gen.Func, needType abi.Type) (reg regs.R, ok bool) {
	debugf("try steal %s variable register", needType)

	opInitVars(f)

	var bestIndex = -1
	var bestRefCount int

	for i, v := range f.Vars {
		if v.Cache.Storage == val.VarReg && v.Cache.Type.Category() == needType.Category() {
			if bestIndex < 0 || v.RefCount < bestRefCount {
				bestIndex = i
				bestRefCount = v.RefCount

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
	v := &f.Vars[bestIndex]
	reg = v.Cache.Reg()
	if v.Dirty {
		index := int32(bestIndex)
		opStoreVar(f, index, val.VarReferenceOperand(v.Cache.Type, index)) // XXX: this is ugly
	}
	v.ResetCache()
	ok = true
	return
}

func opSaveTemporaryOperands(f *gen.Func) {
	debugf("save temporary register operands")

	for i := f.NumPersistentOperands; i < len(f.Operands); i++ {
		x := f.Operands[i]

		switch {
		case x.Storage == val.VarReference:
			f.Vars[x.VarIndex()].RefCount--
			fallthrough
		case x.Storage.IsTempRegOrConditionFlags():
			opInitVars(f)
			opPush(f, x)
			f.Operands[i] = val.StackOperand(x.Type)
		}
	}

	f.NumPersistentOperands = len(f.Operands)
	f.NumStableOperands = len(f.Operands)
}

func opStoreVars(f *gen.Func, forget bool) {
	if forget {
		debugf("store and forget variables")
	} else {
		debugf("store but remember variables")
	}

	for i := range f.Vars {
		v := &f.Vars[i]

		if v.Dirty {
			index := int32(i)
			opStoreVar(f, index, val.VarReferenceOperand(v.Cache.Type, index)) // XXX: this is ugly
			v.Dirty = false
		}

		if forget {
			if v.Cache.Storage == val.VarReg {
				f.Regs.Free(v.Cache.Type, v.Cache.Reg())
			}
			v.ResetCache()
		}
	}
}

func opStoreRegVars(f *gen.Func) {
	debugf("store but remember register variables")

	for i := range f.Vars {
		if v := &f.Vars[i]; v.Cache.Storage == val.VarReg && v.Dirty {
			index := int32(i)
			opStoreVar(f, index, val.VarReferenceOperand(v.Cache.Type, index)) // XXX: this is ugly
			v.Dirty = false
		}
	}
}

func opStoreVar(f *gen.Func, index int32, x val.Operand) {
	x = effectiveOperand(f, x)

	debugf("store variable #%d <- %s", index, x)

	if index >= f.NumInitedVars {
		opInitVarsUntil(f, index, x)
	} else {
		offset := effectiveVarStackOffset(f, index)
		isa.OpStoreStack(f, offset, x)
	}
}
