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
	// Masks are 16-byte aligned for x86-64 SSE.
	ROMask7fAddr32 = iota * 16
	ROMask7fAddr64
	ROMask80Addr32
	ROMask80Addr64
	ROMask5f00Addr32 // 01011111000000000000000000000000
	ROMask43e0Addr64 // 0100001111100000000000000000000000000000000000000000000000000000
	ROTableAddr
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

type MaskBaseAddr int32

const (
	Mask7fBase    = MaskBaseAddr(ROMask7fAddr32)
	Mask80Base    = MaskBaseAddr(ROMask80Addr32)
	MaskTruncBase = MaskBaseAddr(ROMask5f00Addr32)
)

// MaskAddr calculates the absolute read-only data address for reading a mask
// for the given type size.  maskBaseAddr should be one of the Mask*Base
// constants.
func MaskAddr(code Coder, maskBaseAddr MaskBaseAddr, t types.T) int32 {
	return code.RODataAddr() + int32(maskBaseAddr) + int32((t.Size()&8)<<1)
}
