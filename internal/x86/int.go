// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/values"
)

type rexPrefix byte

func (rex rexPrefix) put(text *gen.Text, t abi.Type, ro, index, rmOrBase byte) {
	putRex(text, byte(rex), ro, index, rmOrBase)
}

type rexSizePrefix struct{}

func (rexSizePrefix) put(text *gen.Text, t abi.Type, ro, index, rmOrBase byte) {
	putRexSize(text, t, ro, index, rmOrBase)
}

type data16RexSizePrefix struct{}

func (data16RexSizePrefix) put(text *gen.Text, t abi.Type, ro, index, rmOrBase byte) {
	text.PutByte(0x66)
	putRexSize(text, t, ro, index, rmOrBase)
}

var (
	rex           = rexPrefix(Rex)
	rexW          = rexPrefix(RexW)
	rexSize       rexSizePrefix
	data16RexSize data16RexSizePrefix
)

var (
	constF3RexSize = multiPrefix{constPrefix{0xf3}, rexSize}
)

var (
	neg  = insnRexM{[]byte{0xf7}, 3}
	mul  = insnRexM{[]byte{0xf7}, 4}
	div  = insnRexM{[]byte{0xf7}, 6}
	idiv = insnRexM{[]byte{0xf7}, 7}
	inc  = insnRexM{[]byte{0xff}, 0}
	dec  = insnRexM{[]byte{0xff}, 1}
	rol  = insnRexM{[]byte{0xd3}, 0}
	ror  = insnRexM{[]byte{0xd3}, 1}
	shl  = insnRexM{[]byte{0xd3}, 4}
	shr  = insnRexM{[]byte{0xd3}, 5}
	sar  = insnRexM{[]byte{0xd3}, 7}

	test    = insnPrefix{rexSize, []byte{0x85}, nil}
	cmovb   = insnPrefix{rexSize, []byte{0x0f, 0x42}, nil}
	cmovae  = insnPrefix{rexSize, []byte{0x0f, 0x43}, nil}
	cmove   = insnPrefix{rexSize, []byte{0x0f, 0x44}, nil}
	cmovne  = insnPrefix{rexSize, []byte{0x0f, 0x45}, nil}
	cmovbe  = insnPrefix{rexSize, []byte{0x0f, 0x46}, nil}
	cmova   = insnPrefix{rexSize, []byte{0x0f, 0x47}, nil}
	cmovl   = insnPrefix{rexSize, []byte{0x0f, 0x4c}, nil}
	cmovge  = insnPrefix{rexSize, []byte{0x0f, 0x4d}, nil}
	cmovle  = insnPrefix{rexSize, []byte{0x0f, 0x4e}, nil}
	cmovg   = insnPrefix{rexSize, []byte{0x0f, 0x4f}, nil}
	movzx8  = insnPrefix{rexSize, []byte{0x0f, 0xb6}, nil}
	movzx16 = insnPrefix{rexSize, []byte{0x0f, 0xb7}, nil}
	bsf     = insnPrefix{rexSize, []byte{0x0f, 0xbc}, nil}
	bsr     = insnPrefix{rexSize, []byte{0x0f, 0xbd}, nil}
	movsx8  = insnPrefix{rexSize, []byte{0x0f, 0xbe}, nil}
	movsx16 = insnPrefix{rexSize, []byte{0x0f, 0xbf}, nil}
	movsxd  = insnPrefix{rexW, []byte{0x63}, nil} // variable RexR, RexX and RexB
	popcnt  = insnPrefix{constF3RexSize, []byte{0x0f, 0xb8}, nil}

	xchg = xchgInsn{
		insnRexO{0x90},
		insnPrefix{rexSize, []byte{0x87}, []byte{0x87}},
	}

	movImm = insnPrefixMI{rexSize, 0, 0, 0xc7, 0}

	add = binaryInsn{
		insnPrefix{rexSize, []byte{0x03}, nil},
		insnPrefixMI{rexSize, 0x83, 0, 0x81, 0},
	}
	or = binaryInsn{
		insnPrefix{rexSize, []byte{0x0b}, nil},
		insnPrefixMI{rexSize, 0x83, 0, 0x81, 1},
	}
	and = binaryInsn{
		insnPrefix{rexSize, []byte{0x23}, nil},
		insnPrefixMI{rexSize, 0x83, 0, 0x81, 4},
	}
	sub = binaryInsn{
		insnPrefix{rexSize, []byte{0x2b}, nil},
		insnPrefixMI{rexSize, 0x83, 0, 0x81, 5},
	}
	xor = binaryInsn{
		insnPrefix{rexSize, []byte{0x33}, nil},
		insnPrefixMI{rexSize, 0x83, 0, 0x81, 6},
	}
	cmp = binaryInsn{
		insnPrefix{rexSize, []byte{0x3b}, nil},
		insnPrefixMI{rexSize, 0x83, 0, 0x81, 7},
	}
	mov8 = binaryInsn{
		insnPrefix{rex, []byte{0x8a}, []byte{0x88}},
		insnPrefixMI{rexSize, 0xc6, 0, 0, 0},
	}
	mov16 = binaryInsn{
		insnPrefix{data16RexSize, []byte{0x8b}, []byte{0x89}},
		insnPrefixMI{data16RexSize, 0, 0xc7, 0, 0},
	}
	mov = binaryInsn{
		insnPrefix{rexSize, []byte{0x8b}, []byte{0x89}},
		movImm,
	}

	push = pushPopInsn{
		insnO{0x50},
		insnRexM{[]byte{0xff}, 6},
	}
	pop = pushPopInsn{
		insnO{0x58},
		insnRexM{[]byte{0x8f}, 0},
	}

	rolImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 0},
		insnPrefixMI{rexSize, 0xc1, 0, 0, 0},
	}
	rorImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 1},
		insnPrefixMI{rexSize, 0xc1, 0, 0, 1},
	}
	shlImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 4},
		insnPrefixMI{rexSize, 0xc1, 0, 0, 4},
	}
	shrImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 5},
		insnPrefixMI{rexSize, 0xc1, 0, 0, 5},
	}
	sarImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 7},
		insnPrefixMI{rexSize, 0xc1, 0, 0, 7},
	}

	movImm64 = movImmInsn{
		movImm,
		insnRexOI{0xb8},
	}
)

func isPowerOfTwo(value uint64) bool {
	return (value & (value - 1)) == 0
}

// log2 assumes that value isPowerOfTwo.
func log2(value uint64) (count uint8) {
	for {
		value >>= 1
		if value == 0 {
			return
		}
		count++
	}
}

func inplaceIntOp(m *Module, code gen.Coder, insn insnRexM, x values.Operand) values.Operand {
	reg, _ := opMaybeResultReg(m, code, x, false)
	insn.opReg(&m.Text, x.Type, reg)
	return values.TempRegOperand(x.Type, reg, true)
}
