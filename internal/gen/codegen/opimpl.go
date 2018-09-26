// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/opcode"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/wa"
)

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
	gen  func(*gen.Func, loader.L, opcode.Opcode, opInfo) bool
	info opInfo
}

func init() {
	// avoid reference cycles by initializing some entries lazily:

	opcodeImpls[opcode.Block].gen = genBlock
	opcodeImpls[opcode.Loop].gen = genLoop
	opcodeImpls[opcode.If].gen = genIf

	opcodeSkips[opcode.Block] = skipBlock
	opcodeSkips[opcode.Loop] = skipLoop
	opcodeSkips[opcode.If] = skipIf
}
