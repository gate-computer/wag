// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"io"

	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/types"
	"github.com/tsavola/wag/wasm"
)

const (
	// Mask layout in read-only memory:
	//
	//         +-------- I64 --------+
	//         |                     |
	//         |           +-- I32 --+
	//         |           |         |
	// Offset: 0           4
	// Bytes:  ff ff ff ff ff ff ff 7f  ROMask7fAddr
	//         00 00 00 00 00 00 00 80  ROMask80Addr
	ROMask7fAddr = 0
	ROMask80Addr = 8
	ROTableAddr  = 16
)

const (
	WordSize     = 8              // stack entry size
	StackReserve = WordSize + 128 // trap/import call return address + red zone
)

type OpCoder interface {
	io.Writer
	io.ByteWriter

	Bytes() []byte
	Len() int32

	Align(alignment int, padding byte)
}

type Coder interface {
	OpCoder

	MinMemorySize() wasm.MemorySize
	RODataAddr() int32
	TrapEntryAddr(id traps.Id) int32
	TrapTrampolineAddr(id traps.Id) int32
	OpTrapCall(id traps.Id)

	Discard(values.Operand)
	Consumed(values.Operand)
	RegAllocated(types.T, regs.R) bool
	FreeReg(types.T, regs.R)
}

type RegCoder interface {
	Coder

	TryAllocReg(t types.T) (reg regs.R, ok bool)
	AllocSpecificReg(t types.T, reg regs.R)
}

// TypeMaskAddr calculates the absolute read-only data address for reading a
// mask for the given type size.  baseMaskAddr should be one of the ROMask*Addr
// constants.
func TypeMaskAddr(code Coder, baseMaskAddr int32, t types.T) int32 {
	return code.RODataAddr() + baseMaskAddr + int32(8-t.Size())
}
