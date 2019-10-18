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
	UnaryIntEqz    = 0
	UnaryIntClz    = 1
	UnaryIntCtz    = 2
	UnaryIntPopcnt = 3
	UnaryFloat     = 4

	MaskUnary = 7
)

const (
	IntEqz       = UnaryIntEqz
	IntClz       = UnaryIntClz
	IntCtz       = UnaryIntCtz
	IntPopcnt    = UnaryIntPopcnt
	FloatAbs     = UnaryFloat | uint(in.UnaryFloatAbs)<<8
	FloatNeg     = UnaryFloat | uint(in.UnaryFloatNeg)<<8
	FloatCeil    = UnaryFloat | uint(in.UnaryFloatRIntP)<<8
	FloatFloor   = UnaryFloat | uint(in.UnaryFloatRIntM)<<8
	FloatTrunc   = UnaryFloat | uint(in.UnaryFloatRIntZ)<<8
	FloatNearest = UnaryFloat | uint(in.UnaryFloatRIntN)<<8
	FloatSqrt    = UnaryFloat | uint(in.UnaryFloatSqrt)<<8
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

	MaskBinary = 15
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
	IntAdd        = BinaryIntAddsub | uint(in.AddsubAdd)<<8
	IntSub        = BinaryIntAddsub | uint(in.AddsubSub)<<8
	IntMul        = BinaryIntMul
	IntDivS       = BinaryIntDivS
	IntDivU       = BinaryIntDivU
	IntRemS       = BinaryIntRem | uint(in.DivisionSigned)<<8
	IntRemU       = BinaryIntRem | uint(in.DivisionUnsigned)<<8
	IntAnd        = BinaryIntLogic | uint(in.LogicAnd)<<8
	IntOr         = BinaryIntLogic | uint(in.LogicOrr)<<8
	IntXor        = BinaryIntLogic | uint(in.LogicEor)<<8
	IntShl        = BinaryIntShift | uint(in.VariableShiftL)<<8
	IntShrS       = BinaryIntShift | uint(in.VariableShiftAR)<<8
	IntShrU       = BinaryIntShift | uint(in.VariableShiftLR)<<8
	IntRotl       = BinaryIntRotl
	IntRotr       = BinaryIntShift | uint(in.VariableShiftRR)<<8
	FloatAdd      = BinaryFloat | uint(in.BinaryFloatAdd)<<8
	FloatSub      = BinaryFloat | uint(in.BinaryFloatSub)<<8
	FloatMul      = BinaryFloat | uint(in.BinaryFloatMul)<<8
	FloatDiv      = BinaryFloat | uint(in.BinaryFloatDiv)<<8
	FloatMin      = BinaryFloat | uint(in.BinaryFloatMin)<<8
	FloatMax      = BinaryFloat | uint(in.BinaryFloatMax)<<8
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
	ConvertExtend     = 0
	ConvertMote       = 1
	ConvertFloatToInt = 2
	ConvertIntToFloat = 3

	MaskConvert = 3
)

const (
	ExtendS          = ConvertExtend | uint(in.ExtendS)<<8
	ExtendU          = ConvertExtend | uint(in.ExtendU)<<8
	Demote           = ConvertMote | uint(in.UnaryFloatCvtTo32)<<8
	Promote          = ConvertMote | uint(in.UnaryFloatCvtTo64)<<8
	TruncS           = ConvertFloatToInt | uint(in.TruncFloatS)<<8
	TruncU           = ConvertFloatToInt | uint(in.TruncFloatU)<<8
	ConvertS         = ConvertIntToFloat | uint(in.ConvertIntS)<<8
	ConvertU         = ConvertIntToFloat | uint(in.ConvertIntU)<<8
	ReinterpretInt   = ConvertIntToFloat | uint(in.ReinterpretInt)<<8
	ReinterpretFloat = ConvertFloatToInt | uint(in.ReinterpretFloat)<<8
)
