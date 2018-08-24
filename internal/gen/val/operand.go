// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package val

import (
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen/reg"
)

type Storage uint8

const (
	storageReg  = 1 << 0
	storageVar  = 1 << 1
	storageVSCf = 1 << 2 // Var || Stack || ConditionFlags
	storageTrCf = 1 << 3 // TempReg || ConditionFlags
	storageSCf  = 1 << 4 // Stack || ConditionFlags

	Nowhere        = Storage(0)
	VarReference   = Storage(storageVSCf | storageVar)
	VarReg         = Storage(storageVSCf | storageVar | storageReg)
	TempReg        = Storage(storageTrCf | storageReg)
	Stack          = Storage(storageSCf | storageVSCf)
	ConditionFlags = Storage(storageSCf | storageTrCf | storageVSCf)
	Imm            = Storage((1 << 5))
	BorrowedReg    = Storage((1 << 5) | storageReg)
	VarMem         = Storage((1 << 5) | storageVSCf | storageVar)
)

func (s Storage) IsReg() bool                        { return (s & storageReg) != 0 }
func (s Storage) IsVar() bool                        { return (s & storageVar) != 0 }
func (s Storage) IsVarOrStackOrConditionFlags() bool { return (s & storageVSCf) != 0 }
func (s Storage) IsTempRegOrConditionFlags() bool    { return (s & storageTrCf) != 0 }
func (s Storage) IsStackOrConditionFlags() bool      { return (s & storageSCf) != 0 }

func (s Storage) String() string {
	switch s {
	case Nowhere:
		return "nowhere"

	case VarReference:
		return "variable reference"

	case VarReg:
		return "register variable"

	case TempReg:
		return "temporary register"

	case Stack:
		return "stack"

	case ConditionFlags:
		return "condition flags"

	case Imm:
		return "immediate data"

	case BorrowedReg:
		return "borrorwed register"

	case VarMem:
		return "memory variable"

	default:
		return "<invalid operand storage type>"
	}
}

type Condition int

const (
	Eq = Condition(iota)
	Ne
	GeS
	GtS
	GeU
	GtU
	LeS
	LtS
	LeU
	LtU

	OrderedAndEq
	OrderedAndNe
	OrderedAndGe
	OrderedAndGt
	OrderedAndLe
	OrderedAndLt

	UnorderedOrEq
	UnorderedOrNe
	UnorderedOrGe
	UnorderedOrGt
	UnorderedOrLe
	UnorderedOrLt

	MinOrderedAndCondition  = OrderedAndEq
	MinUnorderedOrCondition = UnorderedOrEq
)

var InvertedConditions = []Condition{
	Eq:            Ne,
	Ne:            Eq,
	GeS:           LtS,
	GtS:           LeS,
	GeU:           LtU,
	GtU:           LeU,
	LeS:           GtS,
	LtS:           GeS,
	LeU:           GtU,
	LtU:           GeU,
	OrderedAndEq:  UnorderedOrNe,
	OrderedAndNe:  UnorderedOrEq,
	OrderedAndGe:  UnorderedOrLt,
	OrderedAndGt:  UnorderedOrLe,
	OrderedAndLe:  UnorderedOrGt,
	OrderedAndLt:  UnorderedOrGe,
	UnorderedOrEq: OrderedAndNe,
	UnorderedOrNe: OrderedAndEq,
	UnorderedOrGe: OrderedAndLt,
	UnorderedOrGt: OrderedAndLe,
	UnorderedOrLe: OrderedAndGt,
	UnorderedOrLt: OrderedAndGe,
}

const (
	payloadZeroExt = uint64(1 << 16)
)

type Bounds struct {
	Upper uint32
}

type Operand struct {
	payload uint64
	Bounds  Bounds
	Type    abi.Type
	Storage Storage
}

func NoOperand(t abi.Type) Operand {
	return Operand{0, Bounds{}, t, Nowhere}
}

func ImmOperand(t abi.Type, payload uint64) Operand {
	return Operand{payload, Bounds{}, t, Imm}
}

func VarReferenceOperand(t abi.Type, index int32) Operand {
	payload := uint64(index) << 32
	return Operand{payload, Bounds{}, t, VarReference}
}

func VarMemOperand(t abi.Type, index, offset int32) Operand {
	payload := (uint64(index) << 32) | uint64(uint32(offset))
	return Operand{payload, Bounds{}, t, VarMem}
}

func VarRegOperand(t abi.Type, index int32, r reg.R, zeroExt bool) Operand {
	payload := (uint64(index) << 32) | uint64(byte(r))
	if zeroExt {
		payload |= payloadZeroExt
	}
	return Operand{payload, Bounds{}, t, VarReg}
}

func TempRegOperand(t abi.Type, r reg.R, zeroExt bool) Operand {
	payload := uint64(byte(r))
	if zeroExt {
		payload |= payloadZeroExt
	}
	return Operand{payload, Bounds{}, t, TempReg}
}

func RegOperand(own bool, t abi.Type, r reg.R) Operand {
	var s Storage
	if own {
		s = TempReg
	} else {
		s = BorrowedReg
	}
	payload := uint64(byte(r))
	return Operand{payload, Bounds{}, t, s}
}

func StackOperand(t abi.Type) Operand {
	return Operand{0, Bounds{}, t, Stack}
}

func ConditionFlagsOperand(cond Condition) Operand {
	payload := uint64(int(cond))
	return Operand{payload, Bounds{}, abi.I32, ConditionFlags}
}

func (o Operand) WithBounds(b Bounds) Operand {
	o.Bounds = b
	return o
}

func (o Operand) ImmValue() int64 {
	if o.Type.Size() == abi.Size32 {
		return int64(int32(uint32(o.payload)))
	} else {
		return int64(o.payload)
	}
}

func (o Operand) Reg() reg.R {
	return reg.R(byte(o.payload))
}

func (o Operand) RegZeroExt() bool {
	return (o.payload & payloadZeroExt) != 0
}

func (o Operand) VarIndex() int32 {
	return int32(o.payload >> 32)
}

func (o Operand) VarMemOffset() int32 {
	return int32(o.payload)
}

func (o Operand) Condition() Condition {
	return Condition(int(o.payload))
}

func (o Operand) String() string {
	switch o.Storage {
	case Nowhere:
		if o.Type == abi.Void {
			return "nothing"
		} else {
			return fmt.Sprintf("placeholder for %s", o.Type)
		}

	case VarReference:
		return fmt.Sprintf("reference to %s variable #%d", o.Type, o.VarIndex())

	case VarReg:
		return fmt.Sprintf("effective variable #%d in %s r%d", o.VarIndex(), o.Type, o.Reg())

	case TempReg:
		return fmt.Sprintf("temporary in %s r%d", o.Type, o.Reg())

	case Stack, ConditionFlags:
		return fmt.Sprintf("%s %s", o.Type, o.Storage)

	case Imm:
		if o.Type.Category() == abi.Int {
			return fmt.Sprintf("immediate %s 0x%x", o.Type, o.payload)
		} else {
			return fmt.Sprintf("immediate %s bits 0x%x", o.Type, o.payload)
		}

	case BorrowedReg:
		return fmt.Sprintf("borrowed in %s r%d", o.Type, o.Reg())

	case VarMem:
		return fmt.Sprintf("effective %s variable #%d at 0x%x", o.Type, o.VarIndex(), o.VarMemOffset())

	default:
		return "<invalid operand>"
	}
}
