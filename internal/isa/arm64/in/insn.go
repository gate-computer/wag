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
	LDRpost = RegRegImm9Size(1<<31 | 7<<27 | 0<<24 | 1<<22 | 0<<21 | 1<<10)

	// Load/store register (immediate pre-indexed)
	STRpre = RegRegImm9Size(1<<31 | 7<<27 | 0<<24 | 0<<22 | 0<<21 | 3<<10)

	// Load/store register (register offset)
	LDRr = RegRegSOptionRegSize(1<<31 | 7<<27 | 0<<24 | 1<<22 | 1<<21 | 2<<10)

	// Load/store register (unscaled immediate)
	STUR = RegRegImm9Size(1<<31 | 7<<27 | 0<<24 | 0<<22 | 0<<21 | 0<<10)
	LDUR = RegRegImm9Size(1<<31 | 7<<27 | 0<<24 | 1<<22 | 0<<21 | 0<<10)

	// Load/store register (unsigned immediate)
	STR = RegRegImm12Size(1<<31 | 7<<27 | 1<<24 | 0<<22)
	LDR = RegRegImm12Size(1<<31 | 7<<27 | 1<<24 | 1<<22)

	// Add/subtract (immediate)
	ADDi  = RegRegImm12ShiftSf(0<<30 | 0<<29 | 0x11<<24)
	ADDSi = RegRegImm12ShiftSf(0<<30 | 1<<29 | 0x11<<24)
	SUBi  = RegRegImm12ShiftSf(1<<30 | 0<<29 | 0x11<<24)
	SUBSi = RegRegImm12ShiftSf(1<<30 | 1<<29 | 0x11<<24)

	// Bitfield
	UBFM = RegRegImm6Imm6NSf(2<<29 | 0x26<<23 | 0<<22)

	// Move wide (immediate)
	MOVN = RegImm16HwSf(0<<29 | 0x25<<23)
	MOVZ = RegImm16HwSf(2<<29 | 0x25<<23)
	MOVK = RegImm16HwSf(3<<29 | 0x25<<23)

	// Address generation
	ADR = RegImm19Imm2(0<<31 | 0x10<<24)

	// Add/subtract (extended register)
	ADDe  = RegRegImm3ExtRegSf(0<<30 | 0<<29 | 0x0b<<24 | 0<<22 | 1<<21)
	SUBSe = RegRegImm3ExtRegSf(1<<30 | 1<<29 | 0x0b<<24 | 0<<22 | 1<<21)

	// Add/subtract (shifted register)
	ADDs  = RegRegImm6RegShiftSf(0<<30 | 0<<29 | 0x0b<<24 | 0<<21)
	SUBs  = RegRegImm6RegShiftSf(1<<30 | 0<<29 | 0x0b<<24 | 0<<21)
	SUBSs = RegRegImm6RegShiftSf(1<<30 | 1<<29 | 0x0b<<24 | 0<<21)

	// Conditional select
	CSEL  = RegRegCondRegSf(0<<30 | 0<<29 | 0xd4<<21 | 0<<10)
	CSINC = RegRegCondRegSf(0<<30 | 0<<29 | 0xd4<<21 | 1<<10)

	// Logical (shifted register)
	ANDs  = RegRegImm6RegShiftSf(0<<29 | 0x0a<<24 | 0<<21)
	ORRs  = RegRegImm6RegShiftSf(1<<29 | 0x0a<<24 | 0<<21)
	ANDSs = RegRegImm6RegShiftSf(3<<29 | 0x0a<<24 | 0<<21)

	// Variable shift
	RORV = RegRegRegSf(0<<30 | 0<<29 | 0xd6<<21 | 0x0b<<10)

	// Bit operations
	RBIT = RegRegSf(1<<30 | 0<<29 | 0xd6<<21 | 0<<16 | 0<<10)
	CLZ  = RegRegSf(1<<30 | 0<<29 | 0xd6<<21 | 0<<16 | 4<<10)

	// Multiply
	MADD = RegRegRegRegSf(0<<29 | 0x1b<<24 | 0<<21 | 0<<15)
	MSUB = RegRegRegRegSf(0<<29 | 0x1b<<24 | 0<<21 | 1<<15)

	// Divide
	UDIV = RegRegRegSf(0<<30 | 0<<29 | 0xd6<<21 | 0x02<<10)
	SDIV = RegRegRegSf(0<<30 | 0<<29 | 0xd6<<21 | 0x03<<10)

	// Floating-point move (register)
	FMOV = RegRegType(0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<17 | 0<<15 | 0x10<<10)

	// Floating-point move (general) - size arguments must be identical
	FMOVtog   = RegRegTypeSf(0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<19 | 6<<16 | 0<<10)
	FMOVfromg = RegRegTypeSf(0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<19 | 7<<16 | 0<<10)

	// Floating-point arithmetic (1 source)
	FNEG = RegRegType(0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<17 | 2<<15 | 0x10<<10)

	// Floating-point comparison
	FCMP = DiscardRegRegType(0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<14 | 8<<10 | 0<<3 | 0<<0)

	// Floating-point conditional select
	FCSEL = RegRegCondRegType(0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 3<<10)

	// System register
	MSR_FPSR = SystemReg(0x354<<22 | 0<<21 | 1<<20 | 0xda21<<5)
	MRS_FPSR = SystemReg(0x354<<22 | 1<<21 | 1<<20 | 0xda21<<5)
)

// Add/subtract instruction variants
type Addsub uint32

const (
	AddsubAdd Addsub = 0 << 30
	AddsubSub Addsub = 1 << 30
)

func (op Addsub) OpcodeImm() RegRegImm12ShiftSf {
	return RegRegImm12ShiftSf(op | 0<<29 | 0x11<<24)
}

func (op Addsub) OpcodeRegExt() RegRegImm3ExtRegSf {
	return RegRegImm3ExtRegSf(op | 0<<29 | 0x0b<<24 | 0<<22 | 1<<21)
}

// Logical instruction variants
type Logic uint32

const (
	LogicAnd Logic = 0 << 29
	LogicOrr Logic = 1 << 29
	LogicEor Logic = 2 << 29
)

func (op Logic) OpcodeImm() RegRegImm6Imm6NSf {
	return RegRegImm6Imm6NSf(op | 0x24<<23)
}

func (op Logic) OpcodeReg() RegRegImm6RegShiftSf {
	return RegRegImm6RegShiftSf(op | 0x0a<<24 | 0<<21)
}

// Bitfield instruction variants
type Bitfield uint32

const (
	ExtendS Bitfield = 0<<29 | 0x26<<23 | 0<<22
	ExtendU Bitfield = 2<<29 | 0x26<<23 | 0<<22
)

func (op Bitfield) Opcode() RegRegImm6Imm6NSf {
	return RegRegImm6Imm6NSf(op)
}

// Data-processing (2 source) instruction variants
type DataProcessing2 uint32

const (
	DivisionUnsigned DataProcessing2 = 0<<30 | 0<<29 | 0xd6<<21 | 0x2<<10
	DivisionSigned   DataProcessing2 = 0<<30 | 0<<29 | 0xd6<<21 | 0x3<<10

	VariableShiftL  DataProcessing2 = 0<<30 | 0<<29 | 0xd6<<21 | 0x8<<10
	VariableShiftLR DataProcessing2 = 0<<30 | 0<<29 | 0xd6<<21 | 0x9<<10
	VariableShiftAR DataProcessing2 = 0<<30 | 0<<29 | 0xd6<<21 | 0xa<<10
	VariableShiftRR DataProcessing2 = 0<<30 | 0<<29 | 0xd6<<21 | 0xb<<10
)

func (op DataProcessing2) OpcodeReg() RegRegRegSf {
	return RegRegRegSf(op)
}

// Floating-point (1 source) instruction variants
type UnaryFloat uint32

const (
	UnaryFloatAbs     UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<17 | 1<<15 | 0x10<<10
	UnaryFloatNeg     UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<17 | 2<<15 | 0x10<<10
	UnaryFloatSqrt    UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<17 | 3<<15 | 0x10<<10
	UnaryFloatCvtTo32 UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<17 | 0<<15 | 0x10<<10
	UnaryFloatCvtTo64 UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<17 | 1<<15 | 0x10<<10

	UnaryFloatRIntN UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<18 | 0<<15 | 0x10<<10
	UnaryFloatRIntP UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<18 | 1<<15 | 0x10<<10
	UnaryFloatRIntM UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<18 | 2<<15 | 0x10<<10
	UnaryFloatRIntZ UnaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<18 | 3<<15 | 0x10<<10
)

func (op UnaryFloat) Opcode() RegRegType {
	return RegRegType(op)
}

// Floating-point (2 source) instruction variants
type BinaryFloat uint32

const (
	BinaryFloatAdd BinaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<13 | 0<<12 | 2<<10
	BinaryFloatSub BinaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<13 | 1<<12 | 2<<10

	BinaryFloatMul BinaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<15 | 0<<12 | 2<<10
	BinaryFloatDiv BinaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | /*****/ 1<<12 | 2<<10

	BinaryFloatMax BinaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<14 | 0<<12 | 2<<10
	BinaryFloatMin BinaryFloat = 0<<31 | 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 1<<14 | 1<<12 | 2<<10
)

func (op BinaryFloat) OpcodeReg() RegRegRegType {
	return RegRegRegType(op)
}

// Floating-point/integer instruction variants
type Conversion uint32

const (
	ConvertIntS      Conversion = 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<19 | 2<<16 | 0<<10 // SCVTF
	ConvertIntU      Conversion = 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<19 | 3<<16 | 0<<10 // UCVTF
	ReinterpretFloat Conversion = 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<19 | 6<<16 | 0<<10 // FMOV
	ReinterpretInt   Conversion = 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 0<<19 | 7<<16 | 0<<10 // FMOV
	TruncFloatS      Conversion = 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 3<<19 | 0<<16 | 0<<10 // FCVTZS
	TruncFloatU      Conversion = 0<<30 | 0<<29 | 0x1e<<24 | 1<<21 | 3<<19 | 1<<16 | 0<<10 // FCVTZU
)

func (op Conversion) Opcode() RegRegTypeSf {
	return RegRegTypeSf(op)
}

// Load/store instruction variants
type Memory uint32

const (
	StoreB   Memory = 0<<30 | 7<<27 | 0<<26 | 0<<24 | 0<<22
	LoadB    Memory = 0<<30 | 7<<27 | 0<<26 | 0<<24 | 1<<22
	LoadSB64 Memory = 0<<30 | 7<<27 | 0<<26 | 0<<24 | 2<<22
	LoadSB32 Memory = 0<<30 | 7<<27 | 0<<26 | 0<<24 | 3<<22
	StoreH   Memory = 1<<30 | 7<<27 | 0<<26 | 0<<24 | 0<<22
	LoadH    Memory = 1<<30 | 7<<27 | 0<<26 | 0<<24 | 1<<22
	LoadSH64 Memory = 1<<30 | 7<<27 | 0<<26 | 0<<24 | 2<<22
	LoadSH32 Memory = 1<<30 | 7<<27 | 0<<26 | 0<<24 | 3<<22
	StoreW   Memory = 2<<30 | 7<<27 | 0<<26 | 0<<24 | 0<<22
	LoadW    Memory = 2<<30 | 7<<27 | 0<<26 | 0<<24 | 1<<22
	LoadSW64 Memory = 2<<30 | 7<<27 | 0<<26 | 0<<24 | 2<<22
	StoreF32 Memory = 2<<30 | 7<<27 | 1<<26 | 0<<24 | 0<<22
	LoadF32  Memory = 2<<30 | 7<<27 | 1<<26 | 0<<24 | 1<<22
	StoreD   Memory = 3<<30 | 7<<27 | 0<<26 | 0<<24 | 0<<22
	LoadD    Memory = 3<<30 | 7<<27 | 0<<26 | 0<<24 | 1<<22
	StoreF64 Memory = 3<<30 | 7<<27 | 1<<26 | 0<<24 | 0<<22
	LoadF64  Memory = 3<<30 | 7<<27 | 1<<26 | 0<<24 | 1<<22
)

func (op Memory) OpcodeUnscaled() RegRegImm9 {
	return RegRegImm9(op | 0<<21 | 0<<10)
}

func (op Memory) OpcodeReg() RegRegSOptionReg {
	return RegRegSOptionReg(op | 1<<21 | 2<<10)
}
