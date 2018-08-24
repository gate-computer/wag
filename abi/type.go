// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package abi

type Type uint8
type Category uint8
type Size uint8

const (
	Int   = Category(0)
	Float = Category(1)

	Size32 = Size(4)
	Size64 = Size(8)

	Void = Type(0)
	I32  = Type(Int) | Type(Size32)
	I64  = Type(Int) | Type(Size64)
	F32  = Type(Float) | Type(Size32)
	F64  = Type(Float) | Type(Size64)

	maskCategory = Int | Float
	maskSize     = Size32 | Size64
)

func (t Type) Category() Category {
	return Category(t) & maskCategory
}

// Size in bytes.
func (t Type) Size() Size {
	return Size(t) & maskSize
}

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
		return "<invalid type>"
	}
}

func (cat Category) String() string {
	switch cat {
	case Int:
		return "int"

	case Float:
		return "float"

	default:
		return "<invalid category>"
	}
}
