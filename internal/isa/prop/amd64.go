// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64
// +build amd64 wagamd64
// +build !wagarm64

package prop

import (
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/isa/amd64/in"
)

// Unary

const (
	IntEqz       = 0
	IntClz       = 1
	IntCtz       = 2
	IntPopcnt    = 3
	FloatAbs     = 4
	FloatNeg     = 5
	FloatRoundOp = 6
	FloatSqrt    = 7

	FloatCeil    = FloatRoundOp | in.RoundModeCeil<<8
	FloatFloor   = FloatRoundOp | in.RoundModeFloor<<8
	FloatTrunc   = FloatRoundOp | in.RoundModeTrunc<<8
	FloatNearest = FloatRoundOp | in.RoundModeNearest<<8
)

// Binary

const (
	BinaryIntALAdd = iota
	BinaryIntALSub
	BinaryIntAL
	BinaryIntCmp
	BinaryIntMul
	BinaryIntDivU
	BinaryIntDivS
	BinaryIntRemU
	BinaryIntRemS
	BinaryIntShift
	BinaryFloatCommon
	BinaryFloatMinmax
	BinaryFloatCmp
	BinaryFloatCopysign

	BinaryMask = 15
)

const (
	IndexMinmaxMin = iota
	IndexMinmaxMax
)

const (
	IntEq         = BinaryIntCmp | condition.Eq<<8
	IntNe         = BinaryIntCmp | condition.Ne<<8
	IntLtS        = BinaryIntCmp | condition.LtS<<8
	IntLtU        = BinaryIntCmp | condition.LtU<<8
	IntGtS        = BinaryIntCmp | condition.GtS<<8
	IntGtU        = BinaryIntCmp | condition.GtU<<8
	IntLeS        = BinaryIntCmp | condition.LeS<<8
	IntLeU        = BinaryIntCmp | condition.LeU<<8
	IntGeS        = BinaryIntCmp | condition.GeS<<8
	IntGeU        = BinaryIntCmp | condition.GeU<<8
	FloatEq       = BinaryFloatCmp | condition.OrderedAndEq<<8
	FloatNe       = BinaryFloatCmp | condition.UnorderedOrNe<<8
	FloatLt       = BinaryFloatCmp | condition.OrderedAndLt<<8
	FloatGt       = BinaryFloatCmp | condition.OrderedAndGt<<8
	FloatLe       = BinaryFloatCmp | condition.OrderedAndLe<<8
	FloatGe       = BinaryFloatCmp | condition.OrderedAndGe<<8
	IntAdd        = BinaryIntALAdd | uint(in.InsnAdd)<<8
	IntSub        = BinaryIntALSub | uint(in.InsnSub)<<8
	IntMul        = BinaryIntMul
	IntDivS       = BinaryIntDivS
	IntDivU       = BinaryIntDivU
	IntRemS       = BinaryIntRemS
	IntRemU       = BinaryIntRemU
	IntAnd        = BinaryIntAL | uint(in.InsnAnd)<<8
	IntOr         = BinaryIntAL | uint(in.InsnOr)<<8
	IntXor        = BinaryIntAL | uint(in.InsnXor)<<8
	IntShl        = BinaryIntShift | uint(in.InsnShl)<<8
	IntShrS       = BinaryIntShift | uint(in.InsnShrS)<<8
	IntShrU       = BinaryIntShift | uint(in.InsnShrU)<<8
	IntRotl       = BinaryIntShift | uint(in.InsnRotl)<<8
	IntRotr       = BinaryIntShift | uint(in.InsnRotr)<<8
	FloatAdd      = BinaryFloatCommon | uint(in.ADDSx)<<8
	FloatSub      = BinaryFloatCommon | uint(in.SUBSx)<<8
	FloatMul      = BinaryFloatCommon | uint(in.MULSx)<<8
	FloatDiv      = BinaryFloatCommon | uint(in.DIVSx)<<8
	FloatMin      = BinaryFloatMinmax | IndexMinmaxMin<<8
	FloatMax      = BinaryFloatMinmax | IndexMinmaxMax<<8
	FloatCopysign = BinaryFloatCopysign
)

// Load

const (
	IndexIntLoad    = 0
	IndexIntLoad8S  = 1
	IndexIntLoad8U  = 2
	IndexIntLoad16S = 3
	IndexIntLoad16U = 4
	IndexIntLoad32S = 5
	IndexIntLoad32U = 6
	IndexFloatLoad  = 7
)

const (
	I32Load    = IndexIntLoad
	I64Load    = IndexIntLoad
	F32Load    = IndexFloatLoad
	F64Load    = IndexFloatLoad
	I32Load8S  = IndexIntLoad8S
	I32Load8U  = IndexIntLoad8U
	I32Load16S = IndexIntLoad16S
	I32Load16U = IndexIntLoad16U
	I64Load8S  = IndexIntLoad8S
	I64Load8U  = IndexIntLoad8U
	I64Load16S = IndexIntLoad16S
	I64Load16U = IndexIntLoad16U
	I64Load32S = IndexIntLoad32S
	I64Load32U = IndexIntLoad32U
)

// Store

const (
	IndexIntStore = iota
	IndexIntStore8
	IndexIntStore16
	IndexIntStore32
	IndexFloatStore
)

const (
	I32Store   = IndexIntStore
	I64Store   = IndexIntStore
	F32Store   = IndexFloatStore
	F64Store   = IndexFloatStore
	I32Store8  = IndexIntStore8
	I32Store16 = IndexIntStore16
	I64Store8  = IndexIntStore8
	I64Store16 = IndexIntStore16
	I64Store32 = IndexIntStore32
)

// Conversion

const (
	ExtendS = iota
	ExtendU
	Mote
	TruncS
	TruncU
	ConvertS
	ConvertU
	Reinterpret

	Demote           = Mote
	Promote          = Mote
	ReinterpretInt   = Reinterpret
	ReinterpretFloat = Reinterpret
)
