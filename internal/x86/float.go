// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/types"
)

type floatSizePrefix struct {
	size32 []byte
	size64 []byte
}

func (p *floatSizePrefix) writeTo(code gen.OpCoder, t types.T, ro, index, rmOrBase byte) {
	switch t.Size() {
	case types.Size32:
		code.Write(p.size32)

	case types.Size64:
		code.Write(p.size64)

	default:
		panic(t)
	}

	writeRexTo(code, 0, ro, index, rmOrBase)
}

var (
	Const66RexSize = multiPrefix{constPrefix{0x66}, RexSize}
	OperandSize    = &floatSizePrefix{nil, []byte{0x66}}
	ScalarSize     = &floatSizePrefix{[]byte{0xf3}, []byte{0xf2}}
	RoundSize      = &floatSizePrefix{[]byte{0x0a}, []byte{0x0b}}
)

var (
	UcomisSSE = insnPrefix{OperandSize, []byte{0x0f, 0x2e}, nil}
	AndpSSE   = insnPrefix{OperandSize, []byte{0x0f, 0x54}, nil}
	OrpSSE    = insnPrefix{OperandSize, []byte{0x0f, 0x56}, nil}
	XorpSSE   = insnPrefix{OperandSize, []byte{0x0f, 0x57}, nil}
	MovSSE    = insnPrefix{Const66RexSize, []byte{0x0f, 0x6e}, []byte{0x0f, 0x7e}}
	PxorSSE   = insnPrefix{Const66RexSize, []byte{0x0f, 0xef}, nil}
	MovsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x10}, []byte{0x0f, 0x11}}
	SqrtsSSE  = insnPrefix{ScalarSize, []byte{0x0f, 0x51}, nil}
	AddsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x58}, nil}
	MulsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x59}, nil}
	Cvts2sSSE = insnPrefix{ScalarSize, []byte{0x0f, 0x5a}, nil} // convert float to float
	SubsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5c}, nil}
	MinsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5d}, nil}
	DivsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5e}, nil}
	MaxsSSE   = insnPrefix{ScalarSize, []byte{0x0f, 0x5f}, nil}

	Cvtsi2sSSE  = insnPrefixRexRM{ScalarSize, []byte{0x0f, 0x2a}}
	CvttsSSE2si = insnPrefixRexRM{ScalarSize, []byte{0x0f, 0x2c}}

	RoundsSSE = insnSuffixRMI{[]byte{0x66, 0x0f, 0x3a}, RoundSize}
)

const (
	floatRoundNearest  = 0x0
	floatRoundDown     = 0x1
	floatRoundUp       = 0x2
	floatRoundTruncate = 0x3
)

func pushFloatOp(code gen.OpCoder, t types.T, source regs.R) {
	Sub.opImm(code, types.I64, regStackPtr, gen.WordSize)
	MovsSSE.opToStack(code, t, source, 0)
}

func popFloatOp(code gen.OpCoder, t types.T, target regs.R) {
	MovsSSE.opFromStack(code, t, target, 0)
	Add.opImm(code, types.I64, regStackPtr, gen.WordSize)
}
