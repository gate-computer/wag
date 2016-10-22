package types

import (
	"fmt"
)

type T uint8
type Category uint8
type Size uint8

const (
	maskInt   = 1
	maskFloat = 2
	mask32    = 4 // value is significant
	mask64    = 8 // value is significant

	maskCategory = maskInt | maskFloat
	maskSize     = mask32 | mask64

	Void = T(0)
	I32  = T(maskInt | mask32)
	I64  = T(maskInt | mask64)
	F32  = T(maskFloat | mask32)
	F64  = T(maskFloat | mask64)

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

	default:
		return "corrupted"
	}
}

func (t T) Scalar() bool {
	return t.Category() != 0
}

func (t T) Category() Category {
	return Category(t & maskCategory)
}

func (t T) Size() Size {
	return Size(t & maskSize)
}

var byEncoding = []T{
	1: I32,
	2: I64,
	3: F32,
	4: F64,
}

func ByEncoding(i uint8) T {
	if i > 0 && int(i) < len(byEncoding) {
		return byEncoding[i]
	}
	panic(fmt.Errorf("unknown type %d", i))
}

func InlineSignatureByEncoding(i uint8) T {
	if int(i) < len(byEncoding) {
		return byEncoding[i]
	}
	panic(fmt.Errorf("unknown inline signature type %d", i))
}

var ByString = map[string]T{
	"void": Void,
	"i32":  I32,
	"i64":  I64,
	"f32":  F32,
	"f64":  F64,
}
