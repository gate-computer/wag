// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64

package prop

import (
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/isa/amd64/in"
)

// Unary

const (
	UnaryIntEqz     = 0
	UnaryIntClz     = 1
	UnaryIntCtz     = 2
	UnaryIntPopcnt  = 3
	UnaryFloatAbs   = 4
	UnaryFloatNeg   = 5
	UnaryFloatRound = 6
	UnaryFloatSqrt  = 7

	MaskUnary = 0x7
)

const (
	IntEqz       = UnaryIntEqz
	IntClz       = UnaryIntClz
	IntCtz       = UnaryIntCtz
	IntPopcnt    = UnaryIntPopcnt
	FloatAbs     = UnaryFloatAbs
	FloatNeg     = UnaryFloatNeg
	FloatCeil    = UnaryFloatRound | in.RoundModeCeil<<8
	FloatFloor   = UnaryFloatRound | in.RoundModeFloor<<8
	FloatTrunc   = UnaryFloatRound | in.RoundModeTrunc<<8
	FloatNearest = UnaryFloatRound | in.RoundModeNearest<<8
	FloatSqrt    = UnaryFloatSqrt
)

// Binary

const (
	BinaryIntALAdd      = 0
	BinaryIntALSub      = 1
	BinaryIntAL         = 2
	BinaryIntCmp        = 3
	BinaryIntMul        = 4
	BinaryIntDivU       = 5
	BinaryIntDivS       = 6
	BinaryIntRemU       = 7
	BinaryIntRemS       = 8
	BinaryIntShift      = 9
	BinaryFloatCommon   = 10
	BinaryFloatMinmax   = 11
	BinaryFloatCmp      = 12
	BinaryFloatCopysign = 13

	MaskBinary = 0xf
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
	IntAdd        = BinaryIntALAdd | uint64(in.InsnAdd)<<8
	IntSub        = BinaryIntALSub | uint64(in.InsnSub)<<8
	IntMul        = BinaryIntMul
	IntDivS       = BinaryIntDivS
	IntDivU       = BinaryIntDivU
	IntRemS       = BinaryIntRemS
	IntRemU       = BinaryIntRemU
	IntAnd        = BinaryIntAL | uint64(in.InsnAnd)<<8
	IntOr         = BinaryIntAL | uint64(in.InsnOr)<<8
	IntXor        = BinaryIntAL | uint64(in.InsnXor)<<8
	IntShl        = BinaryIntShift | uint64(in.InsnShl)<<8
	IntShrS       = BinaryIntShift | uint64(in.InsnShrS)<<8
	IntShrU       = BinaryIntShift | uint64(in.InsnShrU)<<8
	IntRotl       = BinaryIntShift | uint64(in.InsnRotl)<<8
	IntRotr       = BinaryIntShift | uint64(in.InsnRotr)<<8
	FloatAdd      = BinaryFloatCommon | uint64(in.ADDSx)<<8
	FloatSub      = BinaryFloatCommon | uint64(in.SUBSx)<<8
	FloatMul      = BinaryFloatCommon | uint64(in.MULSx)<<8
	FloatDiv      = BinaryFloatCommon | uint64(in.DIVSx)<<8
	FloatMin      = BinaryFloatMinmax | uint64(in.MINSx)<<8
	FloatMax      = BinaryFloatMinmax | uint64(in.MAXSx)<<8
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
	IndexIntStore   = 0
	IndexIntStore8  = 1
	IndexIntStore16 = 2
	IndexIntStore32 = 3
	IndexFloatStore = 4
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
	ConversionExtendS     = 0
	ConversionExtendU     = 1
	ConversionMote        = 2 // Demote or promote.
	ConversionTruncS      = 3
	ConversionTruncU      = 4
	ConversionConvertS    = 5
	ConversionConvertU    = 6
	ConversionReinterpret = 7

	MaskConversion = 0x7
)

const (
	ExtendS          = ConversionExtendS
	ExtendU          = ConversionExtendU
	Demote           = ConversionMote
	Promote          = ConversionMote
	TruncS           = ConversionTruncS
	TruncU           = ConversionTruncU
	ConvertS         = ConversionConvertS
	ConvertU         = ConversionConvertU
	ReinterpretInt   = ConversionReinterpret
	ReinterpretFloat = ConversionReinterpret
)
