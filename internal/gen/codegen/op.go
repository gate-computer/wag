// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/wa"
)

type Opcode byte

func (op Opcode) String() (s string) {
	s = opcodeStrings[op]
	if s == "" {
		s = fmt.Sprintf("0x%02x", byte(op))
	}
	return
}

type opInfo uint32

func (info opInfo) primaryType() wa.Type {
	return wa.Type(uint8(info))
}

func (info opInfo) secondaryType() wa.Type {
	return wa.Type(info >> 8)
}

func (info opInfo) props() uint16 {
	return uint16(info >> 16)
}

type opImpl struct {
	gen  func(*gen.Func, loader.L, Opcode, opInfo) bool
	info opInfo
}

func init() {
	// avoid reference cycles by initializing some entries lazily:

	opcodeImpls[OpcodeBlock].gen = genBlock
	opcodeImpls[OpcodeLoop].gen = genLoop
	opcodeImpls[OpcodeIf].gen = genIf

	opcodeSkips[OpcodeBlock] = skipBlock
	opcodeSkips[OpcodeLoop] = skipLoop
	opcodeSkips[OpcodeIf] = skipIf
}
