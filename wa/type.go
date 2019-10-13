// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wa

type ScalarCategory uint8

const (
	Int   = ScalarCategory(0)
	Float = ScalarCategory(1)
)

func (cat ScalarCategory) String() string {
	switch cat {
	case Int:
		return "int"

	case Float:
		return "float"

	default:
		return "<invalid scalar category>"
	}
}

type Size uint8

const (
	Size32 = Size(4)
	Size64 = Size(8)
)

type Type uint8

const (
	Void = Type(0)
	I32  = Type(4 | Int)
	I64  = Type(8 | Int)
	F32  = Type(4 | Float)
	F64  = Type(8 | Float)
)

// Category of a non-void type.
func (t Type) Category() ScalarCategory {
	return ScalarCategory(t & 1)
}

// Size in bytes.
func (t Type) Size() Size {
	return Size(t) & (4 | 8)
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

var typeEncoding = [16]byte{
	Void: 0x00,
	I32:  0x7f,
	I64:  0x7e,
	F32:  0x7d,
	F64:  0x7c,
}

// Encode as WebAssembly.  Result is undefined if Type representation is not
// valid.
func (t Type) Encode() byte {
	return typeEncoding[t&15]
}
