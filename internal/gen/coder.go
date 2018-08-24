// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"encoding/binary"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/trap"
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

type Buffer interface {
	Bytes() []byte
	Extend(n int) []byte
	PutByte(byte)
	PutBytes([]byte)
}

type Text struct {
	B   Buffer
	pos int32
}

func (text *Text) Pos() int32 {
	return text.pos
}

func (text *Text) Bytes() []byte {
	return text.B.Bytes()
}

func (text *Text) Extend(n int) (b []byte) {
	b = text.B.Extend(n)
	text.pos += int32(n)
	return
}

func (text *Text) PutByte(x byte) {
	text.B.PutByte(x)
	text.pos++
}

func (text *Text) PutBytes(x []byte) {
	text.B.PutBytes(x)
	text.pos += int32(len(x))
}

type Coder interface {
	Consumed(values.Operand)
	Discard(values.Operand)
	OpTrapCall(id trap.Id)
	TrapTrampolineAddr(id trap.Id) int32
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
func MaskAddr(roDataAddr int32, maskBaseAddr MaskBaseAddr, t abi.Type) int32 {
	return roDataAddr + int32(maskBaseAddr) + int32((t.Size()&8)<<1)
}

func PutInt8(code Buffer, value int8) {
	code.PutByte(uint8(value))
}

func PutInt16(code Buffer, value int16) {
	binary.LittleEndian.PutUint16(code.Extend(2), uint16(value))
}

func PutInt32(code Buffer, value int32) {
	binary.LittleEndian.PutUint32(code.Extend(4), uint32(value))
}

func PutInt64(code Buffer, value int64) {
	binary.LittleEndian.PutUint64(code.Extend(8), uint64(value))
}
