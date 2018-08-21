// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wasm

type Type uint8
type Category uint8
type Size uint8

const (
	maskInt   = 1
	maskFloat = 2
	mask32    = 4 // value is significant
	mask64    = 8 // value is significant

	maskCategory = maskInt | maskFloat
	maskSize     = mask32 | mask64

	Void = Type(0)
	I32  = Type(maskInt | mask32)
	I64  = Type(maskInt | mask64)
	F32  = Type(maskFloat | mask32)
	F64  = Type(maskFloat | mask64)

	Int   = Category(maskInt)
	Float = Category(maskFloat)

	Size32 = Size(mask32)
	Size64 = Size(mask64)
)

func (t Type) Category() Category {
	return Category(t & maskCategory)
}

// Size in bytes.
func (t Type) Size() Size {
	return Size(t & maskSize)
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
		return "corrupted"
	}
}
