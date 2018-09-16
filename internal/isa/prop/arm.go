// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wagarm64 arm64,!wagamd64

package prop

import (
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/isa/arm/in"
)

// Unary

const (
	IntEqz = iota
	IntClz
	IntCtz
	IntPopcnt
	FloatAbs
	FloatNeg
	FloatCeil
	FloatFloor
	FloatTrunc
	FloatNearest
	FloatSqrt
)

// Binary

const (
	BinaryIntCmp = iota
	BinaryIntAddsub
	BinaryIntMul
	BinaryIntDivS
	BinaryIntDivU
	BinaryIntRemS
	BinaryIntRemU
	BinaryIntLogic
	BinaryIntShl
	BinaryIntShrS
	BinaryIntShrU
	BinaryIntRotl
	BinaryIntRotr

	BinaryFloatEq
	BinaryFloatNe
	BinaryFloatLt
	BinaryFloatGt
	BinaryFloatLe
	BinaryFloatGe
	BinaryFloatAdd
	BinaryFloatSub
	BinaryFloatMul
	BinaryFloatDiv
	BinaryFloatMin
	BinaryFloatMax
	BinaryFloatCopysign
)

const (
	IntEq         = BinaryIntCmp | uint(condition.Eq)<<8
	IntNe         = BinaryIntCmp | uint(condition.Ne)<<8
	IntLtS        = BinaryIntCmp | uint(condition.LtS)<<8
	IntLtU        = BinaryIntCmp | uint(condition.LtU)<<8
	IntGtS        = BinaryIntCmp | uint(condition.GtS)<<8
	IntGtU        = BinaryIntCmp | uint(condition.GtU)<<8
	IntLeS        = BinaryIntCmp | uint(condition.LeS)<<8
	IntLeU        = BinaryIntCmp | uint(condition.LeU)<<8
	IntGeS        = BinaryIntCmp | uint(condition.GeS)<<8
	IntGeU        = BinaryIntCmp | uint(condition.GeU)<<8
	FloatEq       = BinaryFloatEq
	FloatNe       = BinaryFloatNe
	FloatLt       = BinaryFloatLt
	FloatGt       = BinaryFloatGt
	FloatLe       = BinaryFloatLe
	FloatGe       = BinaryFloatGe
	IntAdd        = BinaryIntAddsub | uint(in.AddsubAdd)<<8
	IntSub        = BinaryIntAddsub | uint(in.AddsubSub)<<8
	IntMul        = BinaryIntMul
	IntDivS       = BinaryIntDivS
	IntDivU       = BinaryIntDivU
	IntRemS       = BinaryIntRemS
	IntRemU       = BinaryIntRemU
	IntAnd        = BinaryIntLogic | uint(in.LogicAnd)<<8
	IntOr         = BinaryIntLogic | uint(in.LogicOrr)<<8
	IntXor        = BinaryIntLogic | uint(in.LogicEor)<<8
	IntShl        = BinaryIntShl
	IntShrS       = BinaryIntShrS
	IntShrU       = BinaryIntShrU
	IntRotl       = BinaryIntRotl
	IntRotr       = BinaryIntRotr
	FloatAdd      = BinaryFloatAdd
	FloatSub      = BinaryFloatSub
	FloatMul      = BinaryFloatMul
	FloatDiv      = BinaryFloatDiv
	FloatMin      = BinaryFloatMin
	FloatMax      = BinaryFloatMax
	FloatCopysign = BinaryFloatCopysign
)

// Load

const (
	I32Load    = in.LoadW
	I64Load    = in.LoadD
	I32Load8S  = in.LoadSB32
	I64Load8S  = in.LoadSB64
	I32Load8U  = in.LoadB
	I64Load8U  = in.LoadB
	I32Load16S = in.LoadSH32
	I64Load16S = in.LoadSH64
	I32Load16U = in.LoadH
	I64Load16U = in.LoadH
	I32Load32S = in.LoadW
	I64Load32S = in.LoadSW64
	I32Load32U = in.LoadW
	I64Load32U = in.LoadW
	F32Load    = 0 // TODO
	F64Load    = 0 // TODO
)

// Store

const (
	I32Store   = in.StoreW
	I64Store   = in.StoreD
	F32Store   = 0 // TODO
	F64Store   = 0 // TODO
	I32Store8  = in.StoreB
	I32Store16 = in.StoreH
	I64Store8  = in.StoreB
	I64Store16 = in.StoreH
	I64Store32 = in.StoreW
)

// Conversion

const (
	ExtendS = iota
	ExtendU
	Demote
	Promote
	TruncS
	TruncU
	ConvertS
	ConvertU
	Reinterpret
)
