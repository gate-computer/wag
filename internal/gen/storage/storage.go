// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package storage

type Storage uint8

const (
	Imm = Storage(iota)
	Stack
	Reg
	Flags
	Unreachable
)

func (s Storage) String() string {
	switch s {
	case Imm:
		return "immediate"

	case Stack:
		return "stack"

	case Reg:
		return "register"

	case Flags:
		return "flags"

	case Unreachable:
		return "unreachable"

	default:
		return "<invalid operand storage type>"
	}
}
