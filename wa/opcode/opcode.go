// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package opcode enumerates WebAssembly instructions.
package opcode

import (
	"fmt"
)

type Opcode byte

func (op Opcode) String() (s string) {
	s = strings[op]
	if s == "" {
		s = fmt.Sprintf("0x%02x", byte(op))
	}
	return
}

type MiscOpcode uint32

func (op MiscOpcode) String() (s string) {
	if uint32(op) >= uint32(len(miscStrings)) {
		return fmt.Sprintf("0x%02x 0x%02x", byte(MiscPrefix), uint32(op))
	}
	return miscStrings[op]
}
