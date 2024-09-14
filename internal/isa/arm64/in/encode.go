// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/wa"
)

// cat sets bit 26 based on type category.
func cat(t wa.Type) uint32 {
	return uint32(t.Category()) << 26
}

// sf sets bit 31 based on size.
func sf(t wa.Size) uint32 {
	bit4 := uint32(t & 8)
	return bit4 << 28
}

// sfN sets bits 22 and 31 based on size.
func sfN(t wa.Size) uint32 {
	bit4 := uint32(t & 8)
	return bit4<<28 | bit4<<19
}

// sizeLSB sets bit 30 based on type size.
func sizeLSB(t wa.Type) uint32 {
	bit4 := uint32(t & 8)
	return bit4 << 27
}

// scalarType sets bit 22 based on size.
func scalarType(t wa.Size) uint32 {
	bit4 := uint32(t & 8)
	return bit4 << 19
}

func Int9(i int32) uint32    { return uint32(i) & 0x1ff }
func Uint12(i uint64) uint32 { return uint32(i) & 0xfff }
func Int14(i int32) uint32   { return uint32(i) & 0x3fff }
func Uint16(i uint64) uint32 { return uint32(i) & 0xffff }
func Int19(i int32) uint32   { return uint32(i) & 0x7ffff }
func Int26(i int32) uint32   { return uint32(i) & 0x3ffffff }

type Cond uint32

const (
	EQ = Cond(0x0) // equal to
	NE = Cond(0x1) // not equal to
	CS = Cond(0x2) // carry set
	CC = Cond(0x3) // carry clear
	MI = Cond(0x4) // minus, negative
	PL = Cond(0x5) // positive or zero
	VS = Cond(0x6) // signed overflow
	VC = Cond(0x7) // no signed overflow
	HI = Cond(0x8) // greater than (unsigned)
	LS = Cond(0x9) // less than or equal to (unsigned)
	GE = Cond(0xa) // greater than or equal to (signed)
	LT = Cond(0xb) // less than (signed)
	GT = Cond(0xc) // greater than (signed)
	LE = Cond(0xd) // less than or equal to (signed)

	HS = CS // greater than or equal to (unsigned)
	LO = CC // less than (unsigned)
)

type S uint32

const (
	Unscaled = S(0 << 12)
	Scaled   = S(1 << 12)
)

type Shift uint32

const (
	LSL = Shift(0 << 22)
	LSR = Shift(1 << 22)
	ASR = Shift(2 << 22)
)

type Ext uint32

const (
	UB = Ext(0 << 13)
	UH = Ext(1 << 13)
	UW = Ext(2 << 13)
	UX = Ext(3 << 13)
	SB = Ext(4 << 13)
	SH = Ext(5 << 13)
	SW = Ext(6 << 13)
	SX = Ext(7 << 13)
)

func SizeZeroExt(t wa.Size) Ext {
	bit3 := uint32(t & 8)
	return UW | Ext(bit3<<10)
}

func SizeSignExt(t wa.Size) Ext {
	bit3 := uint32(t & 8)
	return SW | Ext(bit3<<10)
}

type (
	CondImm19            uint32
	Imm16                uint32
	Imm26                uint32
	Reg                  uint32
	RegImm14Bit          uint32
	RegImm16HwSf         uint32
	RegImm19Imm2         uint32
	RegImm19Size         uint32
	RegRegCondRegSf      uint32
	RegRegImm3ExtRegSf   uint32
	RegRegImm6Imm6NSf    uint32
	RegRegImm6RegShiftSf uint32
	RegRegImm9           uint32
	RegRegImm9Size       uint32
	RegRegImm12ShiftSf   uint32
	RegRegImm12Size      uint32
	RegRegSf             uint32
	RegRegNSf            uint32
	RegRegSOptionReg     uint32
	RegRegSOptionRegSize uint32
	RegRegCondRegType    uint32
	RegRegType           uint32
	RegRegTypeSf         uint32
	RegRegRegSf          uint32
	RegRegRegType        uint32
	RegRegRegRegSf       uint32
	DiscardRegRegType    uint32
	SystemReg            uint32
)

func (op CondImm19) CondI19(cond Cond, imm uint32) uint32 {
	return uint32(op) | imm<<5 | uint32(cond)
}

func (op Imm16) I16(imm uint32) uint32 {
	return uint32(op) | imm
}

func (op Imm26) I26(imm uint32) uint32 {
	return uint32(op) | imm
}

func (op Reg) Rn(rn reg.R) uint32 {
	return uint32(op) | uint32(rn)<<5
}

func (op RegImm14Bit) RtI14Bit(rt reg.R, imm, bit uint32) uint32 {
	return uint32(op) | (bit&0x20)<<26 | (bit&0x1f)<<19 | imm<<5 | uint32(rt)
}

func (op RegImm16HwSf) RdI16Hw(rd reg.R, imm, hw uint32, t wa.Size) uint32 {
	return uint32(op) | sf(t) | hw<<21 | imm<<5 | uint32(rd)
}

func (op RegImm19Imm2) RdI19hiI2lo(r reg.R, hi, lo uint32) uint32 {
	return uint32(op) | lo<<29 | hi<<5 | uint32(r)
}

func (op RegImm19Size) RtI19(r reg.R, imm uint32, t wa.Size) uint32 {
	return uint32(op) | sf(t) | imm<<5 | uint32(r)
}

func (op RegRegCondRegSf) RdRnCondRm(rd, rn reg.R, cond Cond, rm reg.R, t wa.Size) uint32 {
	return uint32(op) | sf(t) | uint32(rm)<<16 | uint32(cond)<<12 | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegImm3ExtRegSf) RdRnI3ExtRm(rd, rn reg.R, imm uint32, option Ext, rm reg.R, t wa.Size) uint32 {
	return uint32(op) | sf(t) | uint32(rm)<<16 | uint32(option) | imm<<10 | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegImm6Imm6NSf) RdRnI6sI6r(rd, rn reg.R, imms, immr uint32, t wa.Size) uint32 {
	return uint32(op) | sfN(t) | immr<<16 | imms<<10 | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegImm6RegShiftSf) RdRnI6RmS2(rd, rn reg.R, imm uint32, rm reg.R, shift Shift, t wa.Size) uint32 {
	return uint32(op) | sf(t) | uint32(shift) | uint32(rm)<<16 | imm<<10 | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegImm9) RtRnI9(rt, rn reg.R, imm uint32) uint32 {
	return uint32(op) | imm<<12 | uint32(rn)<<5 | uint32(rt)
}

func (op RegRegImm9Size) RtRnI9(rt, rn reg.R, imm uint32, t wa.Type) uint32 {
	return uint32(op) | sizeLSB(t) | cat(t) | imm<<12 | uint32(rn)<<5 | uint32(rt)
}

func (op RegRegImm12ShiftSf) RdRnI12S2(rd, rn reg.R, imm, shift uint32, t wa.Size) uint32 {
	return uint32(op) | sf(t) | shift<<22 | imm<<10 | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegImm12Size) RdRnI12(rt, rn reg.R, imm uint32, t wa.Type) uint32 {
	return uint32(op) | sizeLSB(t) | cat(t) | imm<<10 | uint32(rn)<<5 | uint32(rt)
}

func (op RegRegSf) RdRn(rd, rn reg.R, t wa.Size) uint32 {
	return uint32(op) | sf(t) | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegNSf) RdRn(rd, rn reg.R, t wa.Size) uint32 {
	return uint32(op) | sfN(t) | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegSOptionReg) RtRnSOptionRm(rt, rn reg.R, s S, option Ext, rm reg.R) uint32 {
	return uint32(op) | uint32(rm)<<16 | uint32(option) | uint32(s) | uint32(rn)<<5 | uint32(rt)
}

func (op RegRegSOptionRegSize) RtRnSOptionRm(rt, rn reg.R, s S, option Ext, rm reg.R, t wa.Type) uint32 {
	return uint32(op) | sizeLSB(t) | cat(t) | uint32(rm)<<16 | uint32(option) | uint32(s) | uint32(rn)<<5 | uint32(rt)
}

func (op RegRegCondRegType) RdRnCondRm(rd, rn reg.R, cond Cond, rm reg.R, t wa.Size) uint32 {
	return uint32(op) | scalarType(t) | uint32(rm)<<16 | uint32(cond)<<12 | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegType) RdRn(rd, rn reg.R, t wa.Size) uint32 {
	return uint32(op) | scalarType(t) | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegTypeSf) RdRn(rd, rn reg.R, floatType, intType wa.Size) uint32 {
	return uint32(op) | sf(intType) | scalarType(floatType) | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegRegSf) RdRnRm(rd, rn, rm reg.R, t wa.Size) uint32 {
	return uint32(op) | sf(t) | uint32(rm)<<16 | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegRegType) RdRnRm(rd, rn, rm reg.R, t wa.Size) uint32 {
	return uint32(op) | scalarType(t) | uint32(rm)<<16 | uint32(rn)<<5 | uint32(rd)
}

func (op RegRegRegRegSf) RdRnRaRm(rd, rn, ra, rm reg.R, t wa.Size) uint32 {
	return uint32(op) | sf(t) | uint32(rm)<<16 | uint32(ra)<<10 | uint32(rn)<<5 | uint32(rd)
}

func (op DiscardRegRegType) RnRm(rn, rm reg.R, t wa.Size) uint32 {
	return uint32(op) | scalarType(t) | uint32(rm)<<16 | uint32(rn)<<5
}

func (op SystemReg) Rt(rt reg.R) uint32 {
	return uint32(op) | uint32(rt)
}
