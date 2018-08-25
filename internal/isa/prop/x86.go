// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wag_amd64 amd64,!wag_arm64

package prop

import (
	"github.com/tsavola/wag/internal/gen/val"
)

// Unary

const (
	// ROUNDSS/ROUNDSD instruction operands
	roundModeNearest = 0x0
	roundModeFloor   = 0x1
	roundModeCeil    = 0x2
	roundModeTrunc   = 0x3
)

const (
	IntEqz       = 0
	IntClz       = 1
	IntCtz       = 2
	IntPopcnt    = 3
	FloatAbs     = 4
	FloatNeg     = 5
	FloatRoundOp = 6
	FloatSqrt    = 7

	FloatCeil    = FloatRoundOp | (roundModeCeil << 3)
	FloatFloor   = FloatRoundOp | (roundModeFloor << 3)
	FloatTrunc   = FloatRoundOp | (roundModeTrunc << 3)
	FloatNearest = FloatRoundOp | (roundModeNearest << 3)
)

// Binary

const (
	BinaryFloat         = 1 << 10
	BinaryCompare       = 1 << 11 // int or float
	BinaryIntShift      = 1 << 12
	BinaryIntDivmul     = 1 << 13
	BinaryFloatMinmax   = 1 << 12
	BinaryFloatCopysign = 1 << 13
)

const (
	DivmulSign = 1 << 0
	DivmulRem  = 1 << 1
	DivmulMul  = 1 << 2
)

const (
	IndexIntAdd = iota
	IndexIntSub
	IndexIntAnd
	IndexIntOr
	IndexIntXor
)

const (
	IndexShiftShl = iota
	IndexShiftShrU
	IndexShiftShrS
	IndexShiftRotr
	IndexShiftRotl
)

const (
	IndexDivmulDivU = 0
	IndexDivmulDivS = DivmulSign
	IndexDivmulRemU = DivmulRem
	IndexDivmulRemS = DivmulRem | DivmulSign
	IndexDivmulMul  = DivmulMul
)

const (
	IndexFloatAdd = iota
	IndexFloatSub
	IndexFloatMul
	IndexFloatDiv
)

const (
	IndexMinmaxMin = iota
	IndexMinmaxMax
)

const (
	IntEq         = BinaryCompare | val.Eq
	IntNe         = BinaryCompare | val.Ne
	IntLtS        = BinaryCompare | val.LtS
	IntLtU        = BinaryCompare | val.LtU
	IntGtS        = BinaryCompare | val.GtS
	IntGtU        = BinaryCompare | val.GtU
	IntLeS        = BinaryCompare | val.LeS
	IntLeU        = BinaryCompare | val.LeU
	IntGeS        = BinaryCompare | val.GeS
	IntGeU        = BinaryCompare | val.GeU
	FloatEq       = BinaryFloat | BinaryCompare | val.OrderedAndEq
	FloatNe       = BinaryFloat | BinaryCompare | val.UnorderedOrNe
	FloatLt       = BinaryFloat | BinaryCompare | val.OrderedAndLt
	FloatGt       = BinaryFloat | BinaryCompare | val.OrderedAndGt
	FloatLe       = BinaryFloat | BinaryCompare | val.OrderedAndLe
	FloatGe       = BinaryFloat | BinaryCompare | val.OrderedAndGe
	IntAdd        = IndexIntAdd
	IntSub        = IndexIntSub
	IntMul        = BinaryIntDivmul | IndexDivmulMul
	IntDivS       = BinaryIntDivmul | IndexDivmulDivS
	IntDivU       = BinaryIntDivmul | IndexDivmulDivU
	IntRemS       = BinaryIntDivmul | IndexDivmulRemS
	IntRemU       = BinaryIntDivmul | IndexDivmulRemU
	IntAnd        = IndexIntAnd
	IntOr         = IndexIntOr
	IntXor        = IndexIntXor
	IntShl        = BinaryIntShift | IndexShiftShl
	IntShrS       = BinaryIntShift | IndexShiftShrS
	IntShrU       = BinaryIntShift | IndexShiftShrU
	IntRotl       = BinaryIntShift | IndexShiftRotl
	IntRotr       = BinaryIntShift | IndexShiftRotr
	FloatAdd      = BinaryFloat | IndexFloatAdd
	FloatSub      = BinaryFloat | IndexFloatSub
	FloatMul      = BinaryFloat | IndexFloatMul
	FloatDiv      = BinaryFloat | IndexFloatDiv
	FloatMin      = BinaryFloat | BinaryFloatMinmax | IndexMinmaxMin
	FloatMax      = BinaryFloat | BinaryFloatMinmax | IndexMinmaxMax
	FloatCopysign = BinaryFloat | BinaryFloatCopysign
)

// Load

const (
	IndexIntLoad = iota
	IndexIntLoad8S
	IndexIntLoad8U
	IndexIntLoad16S
	IndexIntLoad16U
	IndexIntLoad32S
	IndexIntLoad32U
	IndexFloatLoad
)

const (
	I32Load    = (4 << 8) | IndexIntLoad    // fixed type
	I64Load    = (8 << 8) | IndexIntLoad    // fixed type
	IntLoad8S  = (1 << 8) | IndexIntLoad8S  // type-parametric
	IntLoad8U  = (1 << 8) | IndexIntLoad8U  // type-parametric
	IntLoad16S = (2 << 8) | IndexIntLoad16S // type-parametric
	IntLoad16U = (2 << 8) | IndexIntLoad16U // type-parametric
	IntLoad32S = (4 << 8) | IndexIntLoad32S // type-parametric
	IntLoad32U = (4 << 8) | IndexIntLoad32U // type-parametric
	F32Load    = (4 << 8) | IndexFloatLoad  // fixed type
	F64Load    = (8 << 8) | IndexFloatLoad  // fixed type
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
	I32Store   = (4 << 8) | IndexIntStore   // fixed type
	I64Store   = (8 << 8) | IndexIntStore   // fixed type
	IntStore8  = (1 << 8) | IndexIntStore8  // type-parametric
	IntStore16 = (2 << 8) | IndexIntStore16 // type-parametric
	IntStore32 = (4 << 8) | IndexIntStore32 // type-parametric
	F32Store   = (4 << 8) | IndexFloatStore // fixed type
	F64Store   = (8 << 8) | IndexFloatStore // fixed type
)

// Conversion

const (
	Wrap = iota
	ExtendS
	ExtendU
	Mote
	TruncS
	TruncU
	ConvertS
	ConvertU
	Reinterpret
)

const (
	Demote  = Mote
	Promote = Mote
)
