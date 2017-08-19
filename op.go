// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/types"
)

type opcode byte

func (op opcode) String() (s string) {
	s = opcodeStrings[op]
	if s == "" {
		s = fmt.Sprintf("0x%02x", byte(op))
	}
	return
}

type opInfo uint32

func (info opInfo) primaryType() types.T {
	return types.T(uint8(info))
}

func (info opInfo) secondaryType() types.T {
	return types.T(info >> 8)
}

func (info opInfo) oper() uint16 {
	return uint16(info >> 16)
}

type opImpl struct {
	gen  func(*funcCoder, loader.L, opcode, opInfo) bool
	info opInfo
}

//go:generate go run internal/cmd/opcodes/generate.go internal/design/BinaryEncoding.md opcodes.go

// init references which would cause "initialization loop" compilation errors.
func init() {
	opcodeImpls[opcodeBlock].gen = genBlock
	opcodeImpls[opcodeLoop].gen = genLoop
	opcodeImpls[opcodeIf].gen = genIf

	opcodeSkips[opcodeBlock] = skipBlock
	opcodeSkips[opcodeLoop] = skipLoop
	opcodeSkips[opcodeIf] = skipIf
}
