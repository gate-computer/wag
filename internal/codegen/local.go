// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
)

func genGetLocal(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	localIndex := load.Varuint32()
	if localIndex >= uint32(len(f.vars)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, localIndex))
	}

	pushVarOperand(f, int32(localIndex))
	return
}

func genSetLocal(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	localIndex := load.Varuint32()
	if localIndex >= uint32(len(f.vars)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, localIndex))
	}

	opSetLocal(f, op, int32(localIndex))
	return
}

func genTeeLocal(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	localIndex := load.Varuint32()
	if localIndex >= uint32(len(f.vars)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, localIndex))
	}

	opSetLocal(f, op, int32(localIndex))
	pushVarOperand(f, int32(localIndex))
	return
}

func opSetLocal(f *function, op Opcode, index int32) {
	debugf("setting variable #%d", index)

	v := &f.vars[index]
	t := v.cache.Type

	newValue := popOperand(f)
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

			for i := len(f.operands) - 1; i >= 0; i-- {
				x := f.operands[i]

				if x.Storage == values.VarReference && x.VarIndex() == index {
					reg, ok := f.Regs.Alloc(t)
					if !ok {
						spillUntil = i
						goto spill
					}

					zeroExt := opMove(f, reg, x, true) // TODO: avoid multiple loads
					f.operands[i] = values.TempRegOperand(t, reg, zeroExt)

					v.refCount--
					if v.refCount == 0 {
						goto done
					}
				}
			}

			panic("could not find all variable references")

		spill:
			opInitVars(f)

			for i := 0; i <= spillUntil; i++ {
				x := f.operands[i]
				var done bool

				switch x.Storage {
				case values.VarReference:
					f.vars[x.VarIndex()].refCount--
					done = (x.VarIndex() == index && v.refCount == 0)
					fallthrough
				case values.TempReg, values.ConditionFlags:
					opPush(f, x)
					f.operands[i] = values.StackOperand(x.Type)
				}

				if done {
					goto done
				}
			}

			panic("could not find all variable references")

		done:
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
			reg, ok = opTryAllocVarReg(f, t)
		}

		if ok {
			zeroExt := opMove(f, reg, newValue, false)
			v.cache = values.VarRegOperand(t, index, reg, zeroExt)
			v.dirty = true
		} else {
			// spill to stack
			opStoreVar(f, index, newValue)
			v.cache = values.NoOperand(t)
			v.dirty = false
		}

	case newValue.Storage == values.TempReg:
		var reg regs.R
		var zeroExt bool
		var ok bool

		if valueReg := newValue.Reg(); f.Regs.Allocated(t, valueReg) {
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
				reg, ok = opTryAllocVarReg(f, t)
			}

			if ok {
				// we got a register for the value
				zeroExt = opMove(f, reg, newValue, false)
			}
		}

		if ok {
			v.cache = values.VarRegOperand(t, index, reg, zeroExt)
			v.dirty = true
		} else {
			opStoreVar(f, index, newValue)
			v.cache = values.NoOperand(t)
			v.dirty = false
		}

	default:
		panic(newValue)
	}

	if oldCache.Storage == values.VarReg {
		f.Regs.Free(t, oldCache.Reg())
	}
}
