// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wagamd64 amd64,!wagarm64

package prop

import (
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/isa/x86/in"
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
	BinaryIntAL = iota
	BinaryIntCmp
	BinaryIntDivmul
	BinaryIntShift
	BinaryFloatCommon
	BinaryFloatMinmax
	BinaryFloatCmp
	BinaryFloatCopysign
)

const (
	DivmulRemFlag  = 1
	DivmulInsnMask = in.InsnMul | in.InsnDivU | in.InsnDivS

	IndexDivmulMul  = uint(in.InsnMul)
	IndexDivmulDivU = uint(in.InsnDivU)
	IndexDivmulRemU = uint(in.InsnDivU) | DivmulRemFlag
	IndexDivmulDivS = uint(in.InsnDivS)
	IndexDivmulRemS = uint(in.InsnDivS) | DivmulRemFlag
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
	IntAdd        = BinaryIntAL | uint(in.InsnAdd)<<8
	IntSub        = BinaryIntAL | uint(in.InsnSub)<<8
	IntMul        = BinaryIntDivmul | IndexDivmulMul<<8
	IntDivS       = BinaryIntDivmul | IndexDivmulDivS<<8
	IntDivU       = BinaryIntDivmul | IndexDivmulDivU<<8
	IntRemS       = BinaryIntDivmul | IndexDivmulRemS<<8
	IntRemU       = BinaryIntDivmul | IndexDivmulRemU<<8
	IntAnd        = BinaryIntAL | uint(in.InsnAnd)<<8
	IntOr         = BinaryIntAL | uint(in.InsnOr)<<8
	IntXor        = BinaryIntAL | uint(in.InsnXor)<<8
	IntShl        = BinaryIntShift | uint(in.InsnShl)<<8
	IntShrS       = BinaryIntShift | uint(in.InsnShrS)<<8
	IntShrU       = BinaryIntShift | uint(in.InsnShrU)<<8
	IntRotl       = BinaryIntShift | uint(in.InsnRotl)<<8
	IntRotr       = BinaryIntShift | uint(in.InsnRotr)<<8
	FloatAdd      = BinaryFloatCommon | uint(in.ADDSSD)<<8
	FloatSub      = BinaryFloatCommon | uint(in.SUBSSD)<<8
	FloatMul      = BinaryFloatCommon | uint(in.MULSSD)<<8
	FloatDiv      = BinaryFloatCommon | uint(in.DIVSSD)<<8
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

	LoadIndexMask        = 0x7
	LoadIndexZeroExtFlag = 0x8
)

const (
	I32Load    = 3<<8 | IndexIntLoad | LoadIndexZeroExtFlag
	I64Load    = 7<<8 | IndexIntLoad | LoadIndexZeroExtFlag
	F32Load    = 3<<8 | IndexFloatLoad
	F64Load    = 7<<8 | IndexFloatLoad
	I32Load8S  = 0<<8 | IndexIntLoad8S | LoadIndexZeroExtFlag
	I32Load8U  = 0<<8 | IndexIntLoad8U | LoadIndexZeroExtFlag
	I32Load16S = 1<<8 | IndexIntLoad16S | LoadIndexZeroExtFlag
	I32Load16U = 1<<8 | IndexIntLoad16U | LoadIndexZeroExtFlag
	I64Load8S  = 0<<8 | IndexIntLoad8S | LoadIndexZeroExtFlag
	I64Load8U  = 0<<8 | IndexIntLoad8U | LoadIndexZeroExtFlag
	I64Load16S = 1<<8 | IndexIntLoad16S | LoadIndexZeroExtFlag
	I64Load16U = 1<<8 | IndexIntLoad16U | LoadIndexZeroExtFlag
	I64Load32S = 3<<8 | IndexIntLoad32S
	I64Load32U = 3<<8 | IndexIntLoad32U | LoadIndexZeroExtFlag
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
	I32Store   = 3<<8 | IndexIntStore
	I64Store   = 7<<8 | IndexIntStore
	F32Store   = 3<<8 | IndexFloatStore
	F64Store   = 7<<8 | IndexFloatStore
	I32Store8  = 0<<8 | IndexIntStore8
	I32Store16 = 1<<8 | IndexIntStore16
	I64Store8  = 0<<8 | IndexIntStore8
	I64Store16 = 1<<8 | IndexIntStore16
	I64Store32 = 3<<8 | IndexIntStore32
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

	Demote  = Mote
	Promote = Mote
)
