package types

import (
	"strconv"
)

type Type int

const (
	Void = Type(0)
	I32  = Type(1)
	I64  = Type(2)
	F32  = Type(4)
	F64  = Type(8)
)

func (t Type) String() string {
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

var ByString = map[string]Type{
	"void": Void,
	"i32":  I32,
	"i64":  I64,
	"f32":  F32,
	"f64":  F64,
}
