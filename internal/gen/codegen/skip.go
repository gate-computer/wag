// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/gen/debug"
	"github.com/tsavola/wag/internal/gen/opcode"
	"github.com/tsavola/wag/internal/loader"
)

func skipOps(load loader.L) {
	for {
		op := opcode.Opcode(load.Byte())

		if op == opcode.End {
			return
		}

		skipOp(load, op)
	}
}

func skipThenOps(load loader.L) (haveElse bool) {
	for {
		op := opcode.Opcode(load.Byte())

		switch op {
		case opcode.End:
			return

		case opcode.Else:
			haveElse = true
			return
		}

		skipOp(load, op)
	}
}

func skipOp(load loader.L, op opcode.Opcode) {
	debug.Printf("skip %s", op)
	opcodeSkips[op](load, op)
}

func skipBlock(load loader.L, op opcode.Opcode) {
	load.Varint7() // block type
	skipOps(load)
}

func skipBrTable(load loader.L, op opcode.Opcode) {
	for range load.Count() {
		load.Varuint32() // target
	}
	load.Varuint32() // default target
}

func skipCallIndirect(load loader.L, op opcode.Opcode) {
	load.Varuint32() // type index
	load.Byte()      // reserved
}

func skipIf(load loader.L, op opcode.Opcode) {
	load.Varint7() // block type
	if haveElse := skipThenOps(load); haveElse {
		skipOps(load)
	}
}

func skipLoop(load loader.L, op opcode.Opcode) {
	load.Varint7() // block type
	skipOps(load)
}

func skipMemoryImmediate(load loader.L, op opcode.Opcode) {
	load.Varuint32() // flags
	load.Varuint32() // offset
}

func skipUint32(load loader.L, op opcode.Opcode)    { load.Uint32() }
func skipUint64(load loader.L, op opcode.Opcode)    { load.Uint64() }
func skipVarint32(load loader.L, op opcode.Opcode)  { load.Varint32() }
func skipVarint64(load loader.L, op opcode.Opcode)  { load.Varint64() }
func skipVaruint1(load loader.L, op opcode.Opcode)  { load.Varuint1() }
func skipVaruint32(load loader.L, op opcode.Opcode) { load.Varuint32() }
func skipNothing(load loader.L, op opcode.Opcode)   {}
func badSkip(load loader.L, op opcode.Opcode)       { badOp(op) }
