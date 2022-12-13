// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64

package prop

import (
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/isa/arm64/in"
)

// Unary

const (
	UnaryIntEqz    = 0
	UnaryIntClz    = 1
	UnaryIntCtz    = 2
	UnaryIntPopcnt = 3
	UnaryFloat     = 4

	MaskUnary = 0x7
)

const (
	IntEqz       = UnaryIntEqz
	IntClz       = UnaryIntClz
	IntCtz       = UnaryIntCtz
	IntPopcnt    = UnaryIntPopcnt
	FloatAbs     = UnaryFloat | uint64(in.UnaryFloatAbs)<<8
	FloatNeg     = UnaryFloat | uint64(in.UnaryFloatNeg)<<8
	FloatCeil    = UnaryFloat | uint64(in.UnaryFloatRIntP)<<8
	FloatFloor   = UnaryFloat | uint64(in.UnaryFloatRIntM)<<8
	FloatTrunc   = UnaryFloat | uint64(in.UnaryFloatRIntZ)<<8
	FloatNearest = UnaryFloat | uint64(in.UnaryFloatRIntN)<<8
	FloatSqrt    = UnaryFloat | uint64(in.UnaryFloatSqrt)<<8
)

// Binary

const (
	BinaryIntCmp        = 0
	BinaryIntAddsub     = 1
	BinaryIntMul        = 2
	BinaryIntDivU       = 3
	BinaryIntDivS       = 4
	BinaryIntRem        = 5
	BinaryIntLogic      = 6
	BinaryIntShift      = 7
	BinaryIntRotl       = 8
	BinaryFloatCmp      = 9
	BinaryFloat         = 10
	BinaryFloatCopysign = 11

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
	IntAdd        = BinaryIntAddsub | uint64(in.AddsubAdd)<<8
	IntSub        = BinaryIntAddsub | uint64(in.AddsubSub)<<8
	IntMul        = BinaryIntMul
	IntDivS       = BinaryIntDivS
	IntDivU       = BinaryIntDivU
	IntRemS       = BinaryIntRem | uint64(in.DivisionSigned)<<8
	IntRemU       = BinaryIntRem | uint64(in.DivisionUnsigned)<<8
	IntAnd        = BinaryIntLogic | uint64(in.LogicAnd)<<8
	IntOr         = BinaryIntLogic | uint64(in.LogicOrr)<<8
	IntXor        = BinaryIntLogic | uint64(in.LogicEor)<<8
	IntShl        = BinaryIntShift | uint64(in.VariableShiftL)<<8
	IntShrS       = BinaryIntShift | uint64(in.VariableShiftAR)<<8
	IntShrU       = BinaryIntShift | uint64(in.VariableShiftLR)<<8
	IntRotl       = BinaryIntRotl
	IntRotr       = BinaryIntShift | uint64(in.VariableShiftRR)<<8
	FloatAdd      = BinaryFloat | uint64(in.BinaryFloatAdd)<<8
	FloatSub      = BinaryFloat | uint64(in.BinaryFloatSub)<<8
	FloatMul      = BinaryFloat | uint64(in.BinaryFloatMul)<<8
	FloatDiv      = BinaryFloat | uint64(in.BinaryFloatDiv)<<8
	FloatMin      = BinaryFloat | uint64(in.BinaryFloatMin)<<8
	FloatMax      = BinaryFloat | uint64(in.BinaryFloatMax)<<8
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
	F32Load    = in.LoadF32
	F64Load    = in.LoadF64
)

// Store

const (
	I32Store   = in.StoreW
	I64Store   = in.StoreD
	F32Store   = in.StoreF32
	F64Store   = in.StoreF64
	I32Store8  = in.StoreB
	I32Store16 = in.StoreH
	I64Store8  = in.StoreB
	I64Store16 = in.StoreH
	I64Store32 = in.StoreW
)

// Conversion

const (
	ConversionExtend     = 0
	ConversionMote       = 1
	ConversionFloatToInt = 2
	ConversionIntToFloat = 3

	MaskConversion = 0x3
)

const (
	ExtendS          = ConversionExtend | uint64(in.ExtendS)<<8
	ExtendU          = ConversionExtend | uint64(in.ExtendU)<<8
	Demote           = ConversionMote | uint64(in.UnaryFloatCvtTo32)<<8
	Promote          = ConversionMote | uint64(in.UnaryFloatCvtTo64)<<8
	TruncS           = ConversionFloatToInt | uint64(in.TruncFloatS)<<8
	TruncU           = ConversionFloatToInt | uint64(in.TruncFloatU)<<8
	ConvertS         = ConversionIntToFloat | uint64(in.ConvertIntS)<<8
	ConvertU         = ConversionIntToFloat | uint64(in.ConvertIntU)<<8
	ReinterpretInt   = ConversionIntToFloat | uint64(in.ReinterpretInt)<<8
	ReinterpretFloat = ConversionFloatToInt | uint64(in.ReinterpretFloat)<<8
)
