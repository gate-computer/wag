// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/wasm"
)

type floatSizePrefix struct {
	size32 []byte
	size64 []byte
}

func (p *floatSizePrefix) put(code gen.Buffer, t wasm.Type, ro, index, rmOrBase byte) {
	switch t.Size() {
	case wasm.Size32:
		code.PutBytes(p.size32)

	case wasm.Size64:
		code.PutBytes(p.size64)

	default:
		panic(t)
	}

	putRex(code, 0, ro, index, rmOrBase)
}

var (
	const66RexSize = multiPrefix{constPrefix{0x66}, rexSize}
	operandSize    = &floatSizePrefix{nil, []byte{0x66}}
	scalarSize     = &floatSizePrefix{[]byte{0xf3}, []byte{0xf2}}
	roundSize      = &floatSizePrefix{[]byte{0x0a}, []byte{0x0b}}
)

var (
	movapSSE  = insnPrefix{operandSize, []byte{0x0f, 0x28}, nil}
	ucomisSSE = insnPrefix{operandSize, []byte{0x0f, 0x2e}, nil}
	andpSSE   = insnPrefix{operandSize, []byte{0x0f, 0x54}, nil}
	orpSSE    = insnPrefix{operandSize, []byte{0x0f, 0x56}, nil}
	xorpSSE   = insnPrefix{operandSize, []byte{0x0f, 0x57}, nil}
	movSSE    = insnPrefix{const66RexSize, []byte{0x0f, 0x6e}, []byte{0x0f, 0x7e}}
	pxorSSE   = insnPrefix{const66RexSize, []byte{0x0f, 0xef}, nil}
	movsSSE   = insnPrefix{scalarSize, []byte{0x0f, 0x10}, []byte{0x0f, 0x11}}
	sqrtsSSE  = insnPrefix{scalarSize, []byte{0x0f, 0x51}, nil}
	addsSSE   = insnPrefix{scalarSize, []byte{0x0f, 0x58}, nil}
	mulsSSE   = insnPrefix{scalarSize, []byte{0x0f, 0x59}, nil}
	cvts2sSSE = insnPrefix{scalarSize, []byte{0x0f, 0x5a}, nil} // convert float to float
	subsSSE   = insnPrefix{scalarSize, []byte{0x0f, 0x5c}, nil}
	minsSSE   = insnPrefix{scalarSize, []byte{0x0f, 0x5d}, nil}
	divsSSE   = insnPrefix{scalarSize, []byte{0x0f, 0x5e}, nil}
	maxsSSE   = insnPrefix{scalarSize, []byte{0x0f, 0x5f}, nil}

	cvtsi2sSSE  = insnPrefixRexRM{scalarSize, []byte{0x0f, 0x2a}}
	cvttsSSE2si = insnPrefixRexRM{scalarSize, []byte{0x0f, 0x2c}}

	roundsSSE = insnSuffixRMI{[]byte{0x66, 0x0f, 0x3a}, roundSize}
)

func pushFloatOp(code gen.Buffer, t wasm.Type, source regs.R) {
	sub.opImm(code, wasm.I64, RegStackPtr, gen.WordSize)
	movsSSE.opToStack(code, t, source, 0)
}

func popFloatOp(code gen.Buffer, t wasm.Type, target regs.R) {
	movsSSE.opFromStack(code, t, target, 0)
	add.opImm(code, wasm.I64, RegStackPtr, gen.WordSize)
}
