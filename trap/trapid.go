// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package trap enumerates trap identifiers.
package trap

import (
	"fmt"
)

type ID int

const (
	Exit       = ID(iota)
	NoFunction // Recoverable (nonportable).  Return address must be adjusted.
	Suspended  // Recoverable (portable).
	Unreachable
	CallStackExhausted // Recoverable (portable).
	MemoryAccessOutOfBounds
	IndirectCallIndexOutOfBounds
	IndirectCallSignatureMismatch
	IntegerDivideByZero
	IntegerOverflow
	Breakpoint // Recoverable (portable).

	NumTraps
)

func (id ID) String() string {
	switch id {
	case Exit:
		return "exit"

	case NoFunction:
		return "no function"

	case Suspended:
		return "suspended"

	case Unreachable:
		return "unreachable"

	case CallStackExhausted:
		return "call stack exhausted"

	case MemoryAccessOutOfBounds:
		return "memory access out of bounds"

	case IndirectCallIndexOutOfBounds:
		return "indirect call index out of bounds"

	case IndirectCallSignatureMismatch:
		return "indirect call signature mismatch"

	case IntegerDivideByZero:
		return "integer divide by zero"

	case IntegerOverflow:
		return "integer overflow"

	case Breakpoint:
		return "breakpoint"

	default:
		return fmt.Sprintf("unknown trap %d", id)
	}
}

func (id ID) Error() string {
	return "trap: " + id.String()
}
