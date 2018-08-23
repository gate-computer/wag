// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/loader"
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

func (info opInfo) primaryType() abi.Type {
	return abi.Type(uint8(info))
}

func (info opInfo) secondaryType() abi.Type {
	return abi.Type(info >> 8)
}

func (info opInfo) oper() uint16 {
	return uint16(info >> 16)
}

type opImpl struct {
	gen  func(*function, loader.L, Opcode, opInfo) bool
	info opInfo
}

//go:generate go run ../cmd/opcodes/generate.go ../design/BinaryEncoding.md opcodes.go

func init() {
	// avoid reference cycles by initializing some entries lazily:

	opcodeImpls[OpcodeBlock].gen = genBlock
	opcodeImpls[OpcodeLoop].gen = genLoop
	opcodeImpls[OpcodeIf].gen = genIf

	opcodeSkips[OpcodeBlock] = skipBlock
	opcodeSkips[OpcodeLoop] = skipLoop
	opcodeSkips[OpcodeIf] = skipIf
}
