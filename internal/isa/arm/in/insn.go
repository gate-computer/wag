// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

const (
	// Compare & branch (immediate)
	CBZ  = RegImm19Size(0x1a<<25 | 0<<24)
	CBNZ = RegImm19Size(0x1a<<25 | 1<<24)

	// Conditional branch (immediate)
	Bc = CondImm19(0x2a<<25 | 0<<24 | 0<<4)

	// Exception generation
	BRK = Imm16(0xd4<<24 | 1<<21 | 0<<2 | 0<<0)
	HLT = Imm16(0xd4<<24 | 2<<21 | 0<<2 | 0<<0)

	// Test & branch (immediate)
	TBZ  = RegImm14Bit(0x1b<<25 | 0<<24)
	TBNZ = RegImm14Bit(0x1b<<25 | 1<<24)

	// Unconditional branch (immediate)
	B  = Imm26(0<<31 | 5<<26)
	BL = Imm26(1<<31 | 5<<26)

	// Unconditional branch (register)
	BR  = Reg(0x6b<<25 | 0<<21 | 0x1f<<16 | 0<<10 | 0<<0)
	BLR = Reg(0x6b<<25 | 1<<21 | 0x1f<<16 | 0<<10 | 0<<0)
	RET = Reg(0x6b<<25 | 2<<21 | 0x1f<<16 | 0<<10 | 0<<0)

	// Load/store register (immediate post-indexed)
	STRpost = RegRegImm9Size(1<<31 | 7<<27 | 0<<26 | 0<<24 | 0<<22 | 0<<21 | 1<<10)
	LDRpost = RegRegImm9Size(1<<31 | 7<<27 | 0<<26 | 0<<24 | 1<<22 | 0<<21 | 1<<10)

	// Load/store register (immediate pre-indexed)
	STRpre = RegRegImm9Size(1<<31 | 7<<27 | 0<<26 | 0<<24 | 0<<22 | 0<<21 | 3<<10)
	LDRpre = RegRegImm9Size(1<<31 | 7<<27 | 0<<26 | 0<<24 | 1<<22 | 0<<21 | 3<<10)

	// Load/store register (register offset)
	STRr = RegRegSOptionRegSize(1<<31 | 7<<27 | 0<<26 | 0<<24 | 0<<22 | 1<<21 | 2<<10)
	LDRr = RegRegSOptionRegSize(1<<31 | 7<<27 | 0<<26 | 0<<24 | 1<<22 | 1<<21 | 2<<10)

	// Load/store register (unscaled immediate)
	STUR = RegRegImm9Size(1<<31 | 7<<27 | 0<<26 | 0<<24 | 0<<22 | 0<<21 | 0<<10)
	LDUR = RegRegImm9Size(1<<31 | 7<<27 | 0<<26 | 0<<24 | 1<<22 | 0<<21 | 0<<10)

	// Load/store register (unsigned immediate)
	STR = RegRegImm12Size(1<<31 | 7<<27 | 0<<26 | 1<<24 | 0<<22)
	LDR = RegRegImm12Size(1<<31 | 7<<27 | 0<<26 | 1<<24 | 1<<22)

	// Add/subtract (immediate)
	ADDi  = RegRegImm12ShiftSf(0<<30 | 0<<29 | 0x11<<24)
	ADDSi = RegRegImm12ShiftSf(0<<30 | 1<<29 | 0x11<<24)
	SUBi  = RegRegImm12ShiftSf(1<<30 | 0<<29 | 0x11<<24)
	SUBSi = RegRegImm12ShiftSf(1<<30 | 1<<29 | 0x11<<24)

	// Bitfield
	SBFM = RegRegImm6Imm6NSf(0<<29 | 0x26<<23 | 0<<22)
	BFM  = RegRegImm6Imm6NSf(1<<29 | 0x26<<23 | 0<<22)
	UBFM = RegRegImm6Imm6NSf(2<<29 | 0x26<<23 | 0<<22)

	// Extract
	EXTR = RegRegImm6RegNSf(0<<29 | 0x27<<23 | 0<<21)

	// Logical (immediate)
	ANDi  = RegRegImm6Imm6NSf(0<<29 | 0x24<<23)
	ORRi  = RegRegImm6Imm6NSf(1<<29 | 0x24<<23)
	EORi  = RegRegImm6Imm6NSf(2<<29 | 0x24<<23)
	ANDSi = RegRegImm6Imm6NSf(3<<29 | 0x24<<23)

	// Move wide (immediate)
	MOVN = RegImm16HwSf(0<<29 | 0x25<<23)
	MOVZ = RegImm16HwSf(2<<29 | 0x25<<23)
	MOVK = RegImm16HwSf(3<<29 | 0x25<<23)

	// Address generation
	ADR  = RegImm19Imm2(0<<31 | 0x10<<24)
	ADRP = RegImm19Imm2(1<<31 | 0x10<<24)

	// Add/subtract (extended register)
	ADDe  = RegRegImm3ExtRegSf(0<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 1<<21)
	ADDSe = RegRegImm3ExtRegSf(0<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 1<<21)
	SUBe  = RegRegImm3ExtRegSf(1<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 1<<21)
	SUBSe = RegRegImm3ExtRegSf(1<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 1<<21)

	// Add/subtract (shifted register)
	ADDs  = RegRegImm6RegShiftSf(0<<30 | 0<<29 | 0x0b<<24 | 0<<21)
	ADDSs = RegRegImm6RegShiftSf(0<<30 | 1<<29 | 0x0b<<24 | 0<<21)
	SUBs  = RegRegImm6RegShiftSf(1<<30 | 0<<29 | 0x0b<<24 | 0<<21)
	SUBSs = RegRegImm6RegShiftSf(1<<30 | 1<<29 | 0x0b<<24 | 0<<21)

	// Conditional select
	CSEL  = RegRegCondRegSf(0<<30 | 0<<29 | 0xd4<<21 | 0<<10)
	CSINC = RegRegCondRegSf(0<<30 | 0<<29 | 0xd4<<21 | 1<<10)
	CSINV = RegRegCondRegSf(0<<30 | 1<<29 | 0xd4<<21 | 0<<10)
	CSNEG = RegRegCondRegSf(0<<30 | 1<<29 | 0xd4<<21 | 1<<10)

	// Logical (shifted register)
	ANDs  = RegRegImm6RegShiftSf(0<<29 | 0x0a<<24 | 0<<21)
	BIC   = RegRegImm6RegShiftSf(0<<29 | 0x0a<<24 | 1<<21)
	ORRs  = RegRegImm6RegShiftSf(1<<29 | 0x0a<<24 | 0<<21)
	ORN   = RegRegImm6RegShiftSf(1<<29 | 0x0a<<24 | 1<<21)
	EORs  = RegRegImm6RegShiftSf(2<<29 | 0x0a<<24 | 0<<21)
	EON   = RegRegImm6RegShiftSf(2<<29 | 0x0a<<24 | 1<<21)
	ANDSs = RegRegImm6RegShiftSf(3<<29 | 0x0a<<24 | 0<<21)
	BICS  = RegRegImm6RegShiftSf(3<<29 | 0x0a<<24 | 1<<21)
)

// Add/subtract instruction's "op" field
type Addsub uint8

const (
	AddsubAdd = Addsub(0)
	AddsubSub = Addsub(1)
)

func (op Addsub) OpcodeImm() RegRegImm12ShiftSf {
	return RegRegImm12ShiftSf(0<<30 | uint32(op)<<29 | 0x11<<24)
}

func (op Addsub) OpcodeRegExt() RegRegImm3ExtRegSf {
	return RegRegImm3ExtRegSf(0<<30 | uint32(op)<<29 | 0x0b<<24 | 0<<22 | 1<<21)
}

// Logical instruction's "opc" field
type Logic uint8

const (
	LogicAnd = Logic(0)
	LogicOrr = Logic(1)
	LogicEor = Logic(2)
)

func (op Logic) OpcodeImm() RegRegImm6Imm6NSf {
	return RegRegImm6Imm6NSf(uint32(op)<<29 | 0x24<<23)
}

func (op Logic) OpcodeReg() RegRegImm6RegShiftSf {
	return RegRegImm6RegShiftSf(uint32(op)<<29 | 0x0a<<24 | 0<<21)
}

// Load/store instruction's most significant half-word
type Memory uint16

const (
	StoreB   = Memory(0<<14 | 7<<11 | 0<<10 | 0<<8 | 0<<6)
	LoadB    = Memory(0<<14 | 7<<11 | 0<<10 | 0<<8 | 1<<6)
	LoadSB64 = Memory(0<<14 | 7<<11 | 0<<10 | 0<<8 | 2<<6)
	LoadSB32 = Memory(0<<14 | 7<<11 | 0<<10 | 0<<8 | 3<<6)
	StoreH   = Memory(1<<14 | 7<<11 | 0<<10 | 0<<8 | 0<<6)
	LoadH    = Memory(1<<14 | 7<<11 | 0<<10 | 0<<8 | 1<<6)
	LoadSH64 = Memory(1<<14 | 7<<11 | 0<<10 | 0<<8 | 2<<6)
	LoadSH32 = Memory(1<<14 | 7<<11 | 0<<10 | 0<<8 | 3<<6)
	StoreW   = Memory(2<<14 | 7<<11 | 0<<10 | 0<<8 | 0<<6)
	LoadW    = Memory(2<<14 | 7<<11 | 0<<10 | 0<<8 | 1<<6)
	LoadSW64 = Memory(2<<14 | 7<<11 | 0<<10 | 0<<8 | 2<<6)
	StoreD   = Memory(3<<14 | 7<<11 | 0<<10 | 0<<8 | 0<<6)
	LoadD    = Memory(3<<14 | 7<<11 | 0<<10 | 0<<8 | 1<<6)
)

func (op Memory) OpcodeUnscaled() RegRegImm9 {
	return RegRegImm9(uint32(op) << 16)
}
