package types

import (
	"strconv"
)

type T int

const (
	maskScalar = 1 << 0
	maskSize64 = 1 << 1
	maskFloat  = 1 << 2

	Void = T(0)
	I32  = T(maskScalar)
	I64  = T(maskScalar | maskSize64)
	F32  = T(maskScalar | maskFloat)
	F64  = T(maskScalar | maskSize64 | maskFloat)
)

func (t T) String() string {
	switch t {
	case Void:
		return "void"

	case I32:
		return "i32"

	case I64:
		return "i64"

	case F32:
		return "f32"

	case F64:
		return "f64"

	default:
		return strconv.Itoa(int(t))
	}
}

func (t T) Scalar32() bool {
	return (t & (maskScalar | maskSize64)) == maskScalar
}

func (t T) Scalar64() bool {
	return (t & maskSize64) != 0
}

func (t T) Int() bool {
	return (t & (maskScalar | maskFloat)) == maskScalar
}

func (t T) Float() bool {
	return (t & maskFloat) != 0
}

var ByString = map[string]T{
	"void": Void,
	"i32":  I32,
	"i64":  I64,
	"f32":  F32,
	"f64":  F64,
}
