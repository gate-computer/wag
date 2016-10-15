package opers

import (
	"github.com/tsavola/wag/internal/values"
)

// Unary

const (
	UnaryFloat = 1 << 8
	UnaryRound = 1 << 9
)

const (
	IndexIntClz = iota
	IndexIntCtz
	IndexIntPopcnt
	IndexIntEqz

	IndexFloatSqrt = iota
	IndexFloatAbs
	IndexFloatCopysign
	IndexFloatNeg

	// x86-64 ROUNDSS/ROUNDSD instruction operands
	RoundModeNearest = 0x0
	RoundModeFloor   = 0x1
	RoundModeCeil    = 0x2
	RoundModeTrunc   = 0x3
)

const (
	IntClz    = IndexIntClz
	IntCtz    = IndexIntCtz
	IntPopcnt = IndexIntPopcnt
	IntEqz    = IndexIntEqz

	FloatAbs      = UnaryFloat | IndexFloatAbs
	FloatNeg      = UnaryFloat | IndexFloatNeg
	FloatCopysign = UnaryFloat | IndexFloatCopysign
	FloatSqrt     = UnaryFloat | IndexFloatSqrt

	FloatCeil    = UnaryRound | UnaryFloat | RoundModeCeil
	FloatFloor   = UnaryRound | UnaryFloat | RoundModeFloor
	FloatTrunc   = UnaryRound | UnaryFloat | RoundModeTrunc
	FloatNearest = UnaryRound | UnaryFloat | RoundModeNearest
)

// Binary

const (
	BinaryShift   = 1 << 8
	BinaryDivmul  = 1 << 9
	BinaryCompare = 1 << 10
	BinaryFloat   = 1 << 11

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

	IndexShiftShl = iota
	IndexShiftShrU
	IndexShiftShrS
	IndexShiftRotr
	IndexShiftRotl

	IndexDivmulDivU = 0
	IndexDivmulDivS = DivmulSign
	IndexDivmulRemU = DivmulRem
	IndexDivmulRemS = DivmulRem | DivmulSign
	IndexDivmulMul  = DivmulMul

	IndexFloatAdd = iota
	IndexFloatSub
	IndexFloatMul
	IndexFloatDiv
	IndexFloatMin
	IndexFloatMax
)

const (
	IntAdd = IndexIntAdd
	IntSub = IndexIntSub
	IntAnd = IndexIntAnd
	IntOr  = IndexIntOr
	IntXor = IndexIntXor

	IntShl  = BinaryShift | IndexShiftShl
	IntShrU = BinaryShift | IndexShiftShrU
	IntShrS = BinaryShift | IndexShiftShrS
	IntRotr = BinaryShift | IndexShiftRotr
	IntRotl = BinaryShift | IndexShiftRotl

	IntDivU = BinaryDivmul | IndexDivmulDivU
	IntDivS = BinaryDivmul | IndexDivmulDivS
	IntRemU = BinaryDivmul | IndexDivmulRemU
	IntRemS = BinaryDivmul | IndexDivmulRemS
	IntMul  = BinaryDivmul | IndexDivmulMul

	IntEq  = BinaryCompare | values.Eq
	IntNe  = BinaryCompare | values.Ne
	IntGeS = BinaryCompare | values.GeS
	IntGeU = BinaryCompare | values.GeU
	IntGtS = BinaryCompare | values.GtS
	IntGtU = BinaryCompare | values.GtU
	IntLeS = BinaryCompare | values.LeS
	IntLeU = BinaryCompare | values.LeU
	IntLtS = BinaryCompare | values.LtS
	IntLtU = BinaryCompare | values.LtU

	FloatAdd = BinaryFloat | IndexFloatAdd
	FloatSub = BinaryFloat | IndexFloatSub
	FloatMul = BinaryFloat | IndexFloatMul
	FloatDiv = BinaryFloat | IndexFloatDiv
	FloatMin = BinaryFloat | IndexFloatMin
	FloatMax = BinaryFloat | IndexFloatMax

	FloatEq = BinaryFloat | BinaryCompare | values.OrderedAndEq
	FloatNe = BinaryFloat | BinaryCompare | values.UnorderedOrNe
	FloatGe = BinaryFloat | BinaryCompare | values.OrderedAndGe
	FloatGt = BinaryFloat | BinaryCompare | values.OrderedAndGt
	FloatLe = BinaryFloat | BinaryCompare | values.OrderedAndLe
	FloatLt = BinaryFloat | BinaryCompare | values.OrderedAndLt
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

	Demote  = Mote
	Promote = Mote
)
