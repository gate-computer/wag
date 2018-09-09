// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen/reg"
)

type rexWRXB byte

const (
	Rex  = byte(64)
	RexW = rexWRXB(8) // 64-bit operand size
	RexR = rexWRXB(4) // extension of the ModR/M reg field
	RexX = rexWRXB(2) // extension of the SIB index field
	RexB = rexWRXB(1) // extension of the ModR/M r/m field, SIB base field, or Opcode reg field
)

const (
	OneSize = abi.Type(0) // for instructions which don't use RexW
)

const (
	RexMemory = RexB // RegMemoryBase >= 8
)

func typeRexW(t abi.Type) rexWRXB { return rexWRXB(t) & rexWRXB(abi.Size64) } // RexW == abi.Size64

func regRexR(r reg.R) rexWRXB { return rexWRXB(r>>3) << 2 } // 8..15 => 4
func regRexX(r reg.R) rexWRXB { return rexWRXB(r>>3) << 1 } // 8..15 => 2
func regRexB(r reg.R) rexWRXB { return rexWRXB(r>>3) << 0 } // 8..15 => 1
