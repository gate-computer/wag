// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64,cgo

package arm

import (
	"fmt"
	"strings"
	"syscall"
	"testing"

	"github.com/bnagy/gapstone"
	"github.com/tsavola/wag/buffer"
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/wa"
)

var (
	testEngine gapstone.Engine
)

func init() {
	engine, err := gapstone.New(gapstone.CS_ARCH_ARM64, 0)
	if err != nil {
		panic(err)
	}
	testEngine = engine
}

var testMoveIntImmValues = [][2]uint64{
	{0x8000000000000000, 4},
	{0x8000000000000001, 4},
	{0xffff7fffffffffff, 1},
	{0xffff800000000000, 3},
	{0xffff800000000001, 3},
	{0xffffffff7fffffff, 1},
	{0xffffffff80000000, 2},
	{0xffffffff80000001, 2},
	{0xffffffffffff7fff, 1},
	{0xffffffffffff8000, 1},
	{0xffffffffffff8001, 1},
	{0xfffffffffffffffe, 1},
	{0xffffffffffffffff, 1},
	{0x0000000000000000, 1},
	{0x0000000000000001, 1},
	{0x0000000000000002, 1},
	{0x000000000000007e, 1},
	{0x000000000000007f, 1},
	{0x0000000000000080, 1},
	{0x0000000000007ffe, 1},
	{0x0000000000007fff, 1},
	{0x0000000000008000, 1},
	{0x00000000007ffffe, 2},
	{0x00000000007fffff, 2},
	{0x0000000000800000, 1},
	{0x000000007ffffffe, 2},
	{0x000000007fffffff, 2},
	{0x0000000080000000, 1},
	{0x0000007ffffffffe, 3},
	{0x0000007fffffffff, 3},
	{0x0000008000000000, 1},
	{0x00007ffffffffffe, 3},
	{0x00007fffffffffff, 3},
	{0x0000800000000000, 1},
	{0x007ffffffffffffe, 4},
	{0x007fffffffffffff, 4},
	{0x0080000000000000, 1},
	{0x7ffffffffffffffe, 4},
	{0x7fffffffffffffff, 4},

	{0x000000000000ffff, 1},
	{0x00000000ffffffff, 2},
	{0x0000ffffffffffff, 3},
	{0x7fffffffffffffff, 4},
	{0x7fffffffffff0000, 3},
	{0x7fffffff00000000, 2},
	{0x7fff000000000000, 1},

	{0xffffffffffff0000, 1},
	{0xffffffff00000000, 2},
	{0xffff000000000000, 3},
	{0x8000000000000000, 4},
	{0x800000000000ffff, 3},
	{0x80000000ffffffff, 2},
	{0x8000ffffffffffff, 1},

	{0x00000000000000ff, 1},
	{0x0000000000000ff0, 1},
	{0x000000000000ff00, 1},
	{0x00000000000ff000, 2},
	{0x0000000000ff0000, 1},
	{0x000000000ff00000, 1},
	{0x00000000ff000000, 1},
	{0x0000000ff0000000, 2},
	{0x000000ff00000000, 1},
	{0x00000ff000000000, 1},
	{0x0000ff0000000000, 1},
	{0x000ff00000000000, 2},
	{0x00ff000000000000, 1},
	{0x0ff0000000000000, 1},
	{0xff00000000000000, 4},

	{0xffffffffffffff00, 1},
	{0xfffffffffffff00f, 1},
	{0xffffffffffff00ff, 1},
	{0xfffffffffff00fff, 2},
	{0xffffffffff00ffff, 1},
	{0xfffffffff00fffff, 1},
	{0xffffffff00ffffff, 1},
	{0xfffffff00fffffff, 2},
	{0xffffff00ffffffff, 1},
	{0xfffff00fffffffff, 1},
	{0xffff00ffffffffff, 1},
	{0xfff00fffffffffff, 2},
	{0xff00ffffffffffff, 1},
	{0xf00fffffffffffff, 1},
	{0x00ffffffffffffff, 4},

	{0x000000000000ffff, 1},
	{0x0000000000ffff00, 2},
	{0x00000000ffff0000, 1},
	{0x000000ffff000000, 2},
	{0x0000ffff00000000, 1},
	{0x00ffff0000000000, 2},
	{0xffff000000000000, 3},

	{0xffffffffffff0000, 1},
	{0xffffffffff0000ff, 2},
	{0xffffffff0000ffff, 1},
	{0xffffff0000ffffff, 2},
	{0xffff0000ffffffff, 1},
	{0xff0000ffffffffff, 2},
	{0x0000ffffffffffff, 3},

	{0x0000000000008000, 1},
	{0x0000000000010000, 1},
	{0x0000000000018000, 2},
	{0x0000000080000000, 1},
	{0x0000000100000000, 1},
	{0x0000000180000000, 2},
	{0x0000800000000000, 1},
	{0x0001000000000000, 1},
	{0x0001800000000000, 2},
	{0x0000800000008000, 2},
	{0x0001000000010000, 2},
	{0x0001800000018000, 4},
	{0x0000800080008000, 3},
	{0x0001000100010000, 3},
	{0x0001800180000000, 3},

	{0xffffffffffff7fff, 1},
	{0xfffffffffffeffff, 1},
	{0xfffffffffffe7fff, 2},
	{0xffffffff7fffffff, 1},
	{0xfffffffeffffffff, 1},
	{0xfffffffe7fffffff, 2},
	{0xffff7fffffffffff, 1},
	{0xfffeffffffffffff, 1},
	{0xfffe7fffffffffff, 2},
	{0xffff7fffffff7fff, 2},
	{0xfffefffffffeffff, 2},
	{0xfffe7ffffffe7fff, 4},
	{0xffff7fff7fff7fff, 3},
	{0xfffefffefffeffff, 3},
	{0xfffe7ffe7fffffff, 3},

	{0x0550055000000000, 2},
	{0x0550000005500000, 2},
	{0x0550000000000550, 2},
	{0x0000055005500000, 2},
	{0x0000055000000550, 2},
	{0x0000000005500550, 2},
	{0x0550055005500000, 3},
	{0x0550055000000550, 3},
	{0x0550000005500550, 3},

	{0xfaaffaafffffffff, 2},
	{0xfaaffffffaafffff, 2},
	{0xfaaffffffffffaaf, 2},
	{0xfffffaaffaafffff, 2},
	{0xfffffaaffffffaaf, 2},
	{0xfffffffffaaffaaf, 2},
	{0xfaaffaaffaafffff, 3},
	{0xfaaffaaffffffaaf, 3},
	{0xfaaffffffaaffaaf, 3},

	{0x000000000000002f, 1},
	{0xffffffffffffffd1, 1},
	{0x0000000000001ef7, 1},
	{0xffffffffffffae3c, 1},
	{0x000000002e36bcce, 2},
	{0xffffffff96eabf81, 2},
	{0x00005714ad8bb9ad, 3},
	{0xffffdd452291e454, 3},
	{0x44f6791221da6dc1, 4},
	{0xe282bc7d0d9f9c1c, 4},
}

func TestMoveIntImm(t *testing.T) {
	exe, err := syscall.Mmap(-1, 0, 64, syscall.PROT_NONE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		panic(err)
	}
	defer syscall.Munmap(exe)

	for _, pair := range testMoveIntImmValues {
		data := pair[0]
		val := int64(data)
		expectLen := int(pair[1])

		for _, r := range []reg.R{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			19, 20, 21, 22, 23, 24,
		} {
			if err := syscall.Mprotect(exe, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
				panic(err)
			}

			text := code.Buf{
				Buffer: buffer.NewStatic(exe[:0:len(exe)]),
			}

			moveIntImm(&text, r, val)

			buf := text.Bytes()
			if len(buf) < 4 || len(buf) > 16 {
				t.Errorf("move 0x%016x to %s: code length: %d", data, r, len(buf))
				continue
			}

			insns, err := testEngine.Disasm(buf, 0, 0)
			if err != nil {
				t.Errorf("move 0x%016x to %s: %v", data, r, err)
				continue
			}

			if len(insns) != expectLen {
				t.Errorf("move 0x%016x to %s: wrong number of instructions: %d (expected %d)", data, r, len(insns), expectLen)
			}

			for j, insn := range insns {
				switch {
				case !strings.HasPrefix(insn.Mnemonic, "mov"):
					fallthrough
				case !strings.HasPrefix(insn.OpStr, fmt.Sprintf("x%d, ", r)):
					t.Errorf("move 0x%016x to %s: %s %s (insn #%d)", data, r, insn.Mnemonic, insn.OpStr, j)
				}
			}

			text.PutUint32(in.UBFM.RdRnI6sI6r(RegResult, r, 63, 0, wa.I64))
			text.PutUint32(in.RET.Rn(RegLink))

			if err := syscall.Mprotect(exe, syscall.PROT_EXEC); err != nil {
				panic(err)
			}

			if ret := executeTestCode(exe); ret != data {
				t.Errorf("move 0x%016x to %s: execution result is 0x%016x", data, r, ret)
			}
		}
	}
}

func executeTestCode(exe []byte) uint64
