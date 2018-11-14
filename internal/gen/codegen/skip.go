// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/debug"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/opcode"
)

func skipOps(f *gen.Func, load loader.L) {
	for {
		op := opcode.Opcode(load.Byte())
		f.Map.PutInsnAddr(uint32(f.Text.Addr))

		if op == opcode.End {
			return
		}

		skipOp(f, load, op)
	}
}

func skipThenOps(f *gen.Func, load loader.L) (haveElse bool) {
	for {
		op := opcode.Opcode(load.Byte())
		f.Map.PutInsnAddr(uint32(f.Text.Addr))

		switch op {
		case opcode.End:
			return

		case opcode.Else:
			haveElse = true
			return
		}

		skipOp(f, load, op)
	}
}

func skipOp(f *gen.Func, load loader.L, op opcode.Opcode) {
	debug.Printf("skip %s", op)
	opcodeSkips[op](f, load, op)
}

func skipBlock(f *gen.Func, load loader.L, op opcode.Opcode) {
	load.Varint7() // block type
	skipOps(f, load)
}

func skipBrTable(f *gen.Func, load loader.L, op opcode.Opcode) {
	for range load.Count() {
		load.Varuint32() // target
	}
	load.Varuint32() // default target
}

func skipCallIndirect(f *gen.Func, load loader.L, op opcode.Opcode) {
	load.Varuint32() // type index
	load.Byte()      // reserved
}

func skipIf(f *gen.Func, load loader.L, op opcode.Opcode) {
	load.Varint7() // block type
	if haveElse := skipThenOps(f, load); haveElse {
		skipOps(f, load)
	}
}

func skipLoop(f *gen.Func, load loader.L, op opcode.Opcode) {
	load.Varint7() // block type
	skipOps(f, load)
}

func skipMemoryImmediate(f *gen.Func, load loader.L, op opcode.Opcode) {
	load.Varuint32() // flags
	load.Varuint32() // offset
}

func skipUint32(f *gen.Func, load loader.L, op opcode.Opcode)    { load.Uint32() }
func skipUint64(f *gen.Func, load loader.L, op opcode.Opcode)    { load.Uint64() }
func skipVarint32(f *gen.Func, load loader.L, op opcode.Opcode)  { load.Varint32() }
func skipVarint64(f *gen.Func, load loader.L, op opcode.Opcode)  { load.Varint64() }
func skipVaruint1(f *gen.Func, load loader.L, op opcode.Opcode)  { load.Varuint1() }
func skipVaruint32(f *gen.Func, load loader.L, op opcode.Opcode) { load.Varuint32() }
func skipNothing(f *gen.Func, load loader.L, op opcode.Opcode)   {}
func badSkip(f *gen.Func, load loader.L, op opcode.Opcode)       { badOp(op) }
