package ins

import (
	"strconv"
)

type Type int

const (
	TypeVoid = Type(0)
	TypeI32  = Type(1)
	TypeI64  = Type(2)
	TypeF32  = Type(4)
	TypeF64  = Type(8)
)

func (t Type) String() string {
	switch t {
	case TypeVoid:
		return "void"
	case TypeI32:
		return "i32"
	case TypeI64:
		return "i64"
	case TypeF32:
		return "f32"
	case TypeF64:
		return "f64"
	default:
		return strconv.Itoa(int(t))
	}
}

var Types = map[string]Type{
	"void": TypeVoid,
	"i32":  TypeI32,
	"i64":  TypeI64,
	"f32":  TypeF32,
	"f64":  TypeF64,
}
