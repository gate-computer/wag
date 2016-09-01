package types

import (
	"strconv"
)

type T int
type Category int
type Size int

const (
	maskInt   = 1
	maskFloat = 2
	mask32    = 4 // value is significant
	mask64    = 8 // value is significant
	maskAny   = 16

	maskCategory = maskInt | maskFloat
	maskSize     = mask32 | mask64

	Void = T(0)
	I32  = T(maskInt | mask32)
	I64  = T(maskInt | mask64)
	F32  = T(maskFloat | mask32)
	F64  = T(maskFloat | mask64)

	AnyScalar = T(maskAny | maskInt | mask32) // pseudo
	Any       = T(maskAny)                    // pseudo

	Int   = Category(maskInt)
	Float = Category(maskFloat)

	Size32 = Size(mask32)
	Size64 = Size(mask64)
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

	case AnyScalar:
		return "anyscalar"

	case Any:
		return "any"

	default:
		return strconv.Itoa(int(t))
	}
}

func (t T) Category() Category {
	return Category(t & maskCategory)
}

func (t T) Size() Size {
	return Size(t & maskSize)
}

var ByString = map[string]T{
	"void": Void,
	"i32":  I32,
	"i64":  I64,
	"f32":  F32,
	"f64":  F64,
}
