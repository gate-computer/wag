// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/wa"
)

var nops = [4][4]byte{
	1: {0x90},
	2: {0x66, 0x90},
	3: {0x0f, 0x1f, 0x00},
}

func typeScalarPrefix(t wa.Type) byte { return byte(t)>>2 | 0xf2 } // 0xf3 or 0xf2
func typeRMISizeCode(t wa.Type) byte  { return byte(t)>>3 | 0x0a } // 0x0a or 0x0b

func addrDisp(currentAddr, insnSize, targetAddr int32) int32 {
	if targetAddr != 0 {
		siteAddr := currentAddr + insnSize
		return targetAddr - siteAddr
	} else {
		return -insnSize // infinite loop as placeholder
	}
}

type output struct {
	buf    [16]byte
	offset uint8
}

func (o *output) len() int           { return int(o.offset) }
func (o *output) copy(target []byte) { copy(target, o.buf[:o.offset]) }
func (o *output) debugPrint()        { debugPrintInsn(o.buf[:o.offset]) }

func (o *output) byte(b byte) {
	o.buf[o.offset] = b
	o.offset++
}

func (o *output) byteIf(b byte, condition bool) {
	o.buf[o.offset] = b
	o.offset += bit(condition)
}

// word appends the two bytes of a big-endian word.
func (o *output) word(w uint16) {
	binary.BigEndian.PutUint16(o.buf[o.offset:], w)
	o.offset += 2
}

func (o *output) rex(wrxb rexWRXB) {
	o.buf[o.offset] = Rex | byte(wrxb)
	o.offset++
}

func (o *output) rexIf(wrxb rexWRXB) {
	o.buf[o.offset] = Rex | byte(wrxb)
	o.offset += bit(wrxb != 0)
}

func (o *output) mod(mod Mod, ro ModRO, rm ModRM) {
	o.buf[o.offset] = byte(mod) | byte(ro) | byte(rm)
	o.offset++
}

func (o *output) sib(s Scale, i Index, b Base) {
	o.buf[o.offset] = byte(s) | byte(i) | byte(b)
	o.offset++
}

func (o *output) int8(val int8) {
	o.buf[o.offset] = uint8(val)
	o.offset++
}

func (o *output) int16(val int16) {
	binary.LittleEndian.PutUint16(o.buf[o.offset:], uint16(val))
	o.offset += 2
}

func (o *output) int32(val int32) {
	binary.LittleEndian.PutUint32(o.buf[o.offset:], uint32(val))
	o.offset += 4
}

func (o *output) int64(val int64) {
	binary.LittleEndian.PutUint64(o.buf[o.offset:], uint64(val))
	o.offset += 8
}

func (o *output) int(val int32, size uint8) {
	// Little-endian byte order works for any size
	binary.LittleEndian.PutUint32(o.buf[o.offset:], uint32(val))
	o.offset += size
}

// NP

type NP byte

func (op NP) Type(text *code.Buf, t wa.Type) {
	var o output
	o.rexIf(typeRexW(t))
	o.byte(byte(op))
	o.copy(text.Extend(o.len()))
}

func (op NP) Simple(text *code.Buf) {
	text.PutByte(byte(op))
}

// NP with fixed 0xf3 prefix

type NPprefix byte

func (op NPprefix) Simple(text *code.Buf) {
	var o output
	o.byte(0xf3)
	o.byte(byte(op))
	o.copy(text.Extend(o.len()))
}

// O

type O byte

func (op O) RegResult(text *code.Buf)  { text.PutByte(byte(op) + byte(RegResult)) }
func (op O) RegScratch(text *code.Buf) { text.PutByte(byte(op) + byte(RegScratch)) }
func (op O) RegZero(text *code.Buf)    { text.PutByte(byte(op) + byte(RegZero)) }

// M

type M uint16 // opcode byte and ModRO byte

func (op M) Reg(text *code.Buf, t wa.Type, r reg.R) {
	var o output
	o.rexIf(typeRexW(t) | regRexB(r))
	o.byte(byte(op >> 8))
	o.mod(ModReg, ModRO(op), regRM(r))
	o.copy(text.Extend(o.len()))
}

// M instructions which require rex byte with register operand

type Mex2 uint16 // two opcode bytes

func (op Mex2) OneSizeReg(text *code.Buf, r reg.R) {
	var o output
	o.rex(regRexB(r))
	o.word(uint16(op))
	o.mod(ModReg, 0, regRM(r))
	o.copy(text.Extend(o.len()))
}

// RM (MR)

type RM byte    // opcode byte
type RM2 uint16 // two opcode bytes

func (op RM) RegReg(text *code.Buf, t wa.Type, r, r2 reg.R) {
	var o output
	o.rexIf(typeRexW(t) | regRexR(r) | regRexB(r2))
	o.byte(byte(op))
	o.mod(ModReg, regRO(r), regRM(r2))
	o.copy(text.Extend(o.len()))
}

func (op RM2) RegReg(text *code.Buf, t wa.Type, r, r2 reg.R) {
	var o output
	o.rexIf(typeRexW(t) | regRexR(r) | regRexB(r2))
	o.word(uint16(op))
	o.mod(ModReg, regRO(r), regRM(r2))
	o.copy(text.Extend(o.len()))
}

func (op RM) RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base BaseReg, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rexIf(typeRexW(t) | regRexR(r) | regRexB(reg.R(base)))
	o.byte(byte(op))
	o.mod(mod, regRO(r), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

func (op RM2) RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base BaseReg, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rexIf(typeRexW(t) | regRexR(r) | regRexB(reg.R(base)))
	o.word(uint16(op))
	o.mod(mod, regRO(r), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

func (op RM) RegMemIndexDisp(text *code.Buf, t wa.Type, r reg.R, base BaseReg, index reg.R, s Scale, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rexIf(typeRexW(t) | regRexR(r) | regRexX(index) | regRexB(reg.R(base)))
	o.byte(byte(op))
	o.mod(mod, regRO(r), ModRMSIB)
	o.sib(s, regIndex(index), regBase(reg.R(base)))
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

func (op RM2) RegStack(text *code.Buf, t wa.Type, r reg.R) {
	var o output
	o.rexIf(typeRexW(t) | regRexR(r))
	o.word(uint16(op))
	o.mod(ModMem, regRO(r), ModRMSIB)
	o.sib(Scale0, noIndex, baseStack)
	o.copy(text.Extend(o.len()))
}

func (op RM) RegStackDisp(text *code.Buf, t wa.Type, r reg.R, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rexIf(typeRexW(t) | regRexR(r))
	o.byte(byte(op))
	o.mod(mod, regRO(r), ModRMSIB)
	o.sib(Scale0, noIndex, baseStack)
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

func (op RM2) RegStackDisp(text *code.Buf, t wa.Type, r reg.R, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rexIf(typeRexW(t) | regRexR(r))
	o.word(uint16(op))
	o.mod(mod, regRO(r), ModRMSIB)
	o.sib(Scale0, noIndex, baseStack)
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

func (op RM) RegStackDisp8(text *code.Buf, t wa.Type, r reg.R, disp int8) {
	var o output
	o.rexIf(typeRexW(t) | regRexR(r))
	o.byte(byte(op))
	o.mod(ModMemDisp8, regRO(r), ModRMSIB)
	o.sib(Scale0, noIndex, baseStack)
	o.int8(disp)
	o.copy(text.Extend(o.len()))
}

func (op RM) RegStackStub32(text *code.Buf, t wa.Type, r reg.R) {
	var o output
	o.rexIf(typeRexW(t) | regRexR(r))
	o.byte(byte(op))
	o.mod(ModMemDisp32, regRO(r), ModRMSIB)
	o.sib(Scale0, noIndex, baseStack)
	o.int32(-0x80000000) // out-of-bounds as placeholder
	o.copy(text.Extend(o.len()))
}

// RM (MR) with prefix and two opcode bytes (first byte hardcoded)

type RMprefix uint16 // fixed-length prefix and second opcode byte
type RMscalar byte   // second opcode byte; type-dependent fixed-length prefix
type RMpacked byte   // second opcode byte; type-dependent variable-length prefix

func (op RMprefix) RegReg(text *code.Buf, t wa.Type, r, r2 reg.R) {
	var o output
	o.byte(byte(op >> 8))
	o.rexIf(typeRexW(t) | regRexR(r) | regRexB(r2))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(ModReg, regRO(r), regRM(r2))
	o.copy(text.Extend(o.len()))
}

func (op RMscalar) RegReg(text *code.Buf, t wa.Type, r, r2 reg.R) {
	var o output
	o.byte(typeScalarPrefix(t))
	o.rexIf(regRexR(r) | regRexB(r2))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(ModReg, regRO(r), regRM(r2))
	o.copy(text.Extend(o.len()))
}

func (op RMpacked) RegReg(text *code.Buf, t wa.Type, r, r2 reg.R) {
	var o output
	o.byteIf(0x66, t&8 == 8)
	o.rexIf(regRexR(r) | regRexB(r2))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(ModReg, regRO(r), regRM(r2))
	o.copy(text.Extend(o.len()))
}

func (op RMscalar) TypeRegReg(text *code.Buf, floatType, intType wa.Type, r, r2 reg.R) {
	var o output
	o.byte(typeScalarPrefix(floatType))
	o.rexIf(typeRexW(intType) | regRexR(r) | regRexB(r2))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(ModReg, regRO(r), regRM(r2))
	o.copy(text.Extend(o.len()))
}

func (op RMprefix) RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base BaseReg, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.byte(byte(op >> 8))
	o.rexIf(typeRexW(t) | regRexR(r) | regRexB(reg.R(base)))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(mod, regRO(r), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

func (op RMscalar) RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base BaseReg, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.byte(typeScalarPrefix(t))
	o.rexIf(regRexR(r) | regRexB(reg.R(base)))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(mod, regRO(r), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

func (op RMpacked) RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base BaseReg, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.byteIf(0x66, t&8 == 8)
	o.rexIf(regRexR(r) | regRexB(reg.R(base)))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(mod, regRO(r), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

func (op RMprefix) RegStack(text *code.Buf, t wa.Type, r reg.R) {
	var o output
	o.byte(byte(op >> 8))
	o.rexIf(typeRexW(t) | regRexR(r))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(ModMem, regRO(r), ModRMSIB)
	o.sib(Scale0, noIndex, baseStack)
	o.copy(text.Extend(o.len()))
}

func (op RMprefix) RegStackDisp(text *code.Buf, t wa.Type, r reg.R, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.byte(byte(op >> 8))
	o.rexIf(typeRexW(t) | regRexR(r))
	o.byte(0x0f)
	o.byte(byte(op))
	o.mod(mod, regRO(r), ModRMSIB)
	o.sib(Scale0, noIndex, baseStack)
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

// RM instructions with 8-bit operand size

type RMdata8 byte // opcode byte

func (op RMdata8) RegMemDisp(text *code.Buf, _ wa.Type, r reg.R, base BaseReg, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rex(regRexR(r) | regRexB(reg.R(base)))
	o.byte(byte(op))
	o.mod(mod, regRO(r), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

// RM instructions with 16-bit operand size

type RMdata16 byte // opcode byte

func (op RMdata16) RegMemDisp(text *code.Buf, _ wa.Type, r reg.R, base BaseReg, disp int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.byte(0x66)
	o.rexIf(regRexR(r) | regRexB(reg.R(base)))
	o.byte(byte(op))
	o.mod(mod, regRO(r), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.copy(text.Extend(o.len()))
}

// I

type Ipush byte // opcode of instruction variant with 8-bit immediate

func (op Ipush) Imm(text *code.Buf, val int32) {
	var valSize = immSize(val)
	var o output
	o.byte(byte(op) &^ (valSize >> 1)) // 0x6a => 0x68 if 32-bit
	o.int(val, valSize)
	o.copy(text.Extend(o.len()))
}

// OI

type OI byte

func (op OI) RegImm64(text *code.Buf, r reg.R, val int64) {
	var o output
	o.rex(RexW | regRexB(r))
	o.byte(byte(op) + byte(r)&7)
	o.int64(val)
	o.copy(text.Extend(o.len()))
}

// MI instructions with varying operand and immediate sizes

type MI uint32 // opcode bytes for 32-bit value and 8-bit value; and common ModRO byte

func (ops MI) RegImm(text *code.Buf, t wa.Type, r reg.R, val int32) {
	var op, valSize = immOpcodeSize(uint16(ops>>8), val)
	var o output
	o.rexIf(typeRexW(t) | regRexB(r))
	o.byte(op)
	o.mod(ModReg, ModRO(ops), regRM(r))
	o.int(val, valSize)
	o.copy(text.Extend(o.len()))
}

func (op MI) RegImm8(text *code.Buf, t wa.Type, r reg.R, val int8) {
	var o output
	o.rexIf(typeRexW(t) | regRexB(r))
	o.byte(byte(op >> 8))
	o.mod(ModReg, ModRO(op), regRM(r))
	o.int8(val)
	o.copy(text.Extend(o.len()))
}

func (op MI) RegImm32(text *code.Buf, t wa.Type, r reg.R, val int32) {
	var o output
	o.rexIf(typeRexW(t) | regRexB(r))
	o.byte(byte(op >> 16))
	o.mod(ModReg, ModRO(op), regRM(r))
	o.int32(val)
	o.copy(text.Extend(o.len()))
}

func (op MI) StackDispImm32(text *code.Buf, t wa.Type, disp, val int32) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rexIf(typeRexW(t))
	o.byte(byte(op >> 16))
	o.mod(mod, ModRO(op), ModRMSIB)
	o.sib(Scale0, noIndex, baseStack)
	o.int(disp, dispSize)
	o.int32(val)
	o.copy(text.Extend(o.len()))
}

// MI instructions with 8-bit operand size implementing generic interface

type MI8 uint16 // opcode byte and ModRO byte

func (op MI8) OneSizeRegImm(text *code.Buf, r reg.R, val8 int64) {
	var o output
	o.rex(regRexB(r))
	o.byte(byte(op >> 8))
	o.mod(ModReg, ModRO(op), regRM(r))
	o.int8(int8(val8))
	o.copy(text.Extend(o.len()))
}

// MemDispImm ignores the type argument.
func (op MI8) MemDispImm(text *code.Buf, _ wa.Type, base BaseReg, disp int32, val8 int64) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rexIf(regRexB(reg.R(base)))
	o.byte(byte(op >> 8))
	o.mod(mod, ModRO(op), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.int8(int8(val8))
	o.copy(text.Extend(o.len()))
}

// MI instructions with 16-bit operand size implementing generic interface

type MI16 uint16 // opcode byte and ModRO byte

// MemDispImm ignores the type argument.
func (op MI16) MemDispImm(text *code.Buf, _ wa.Type, base BaseReg, disp int32, val16 int64) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.byte(0x66)
	o.rexIf(regRexB(reg.R(base)))
	o.byte(byte(op >> 8))
	o.mod(mod, ModRO(op), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.int16(int16(val16))
	o.copy(text.Extend(o.len()))
}

// MI instructions with 32-bit immediate implementing generic interface

type MI32 uint16 // opcode byte and ModRO byte

func (op MI32) MemDispImm(text *code.Buf, t wa.Type, base BaseReg, disp int32, val32 int64) {
	var mod, dispSize = dispModSize(disp)
	var o output
	o.rexIf(typeRexW(t) | regRexB(reg.R(base)))
	o.byte(byte(op >> 8))
	o.mod(mod, ModRO(op), regRM(reg.R(base)))
	o.int(disp, dispSize)
	o.int32(int32(val32))
	o.copy(text.Extend(o.len()))
}

// RMI with prefix, two opcode bytes (first byte hardcoded) and size code

type RMIscalar byte // second opcode byte; uses constant fixed-length prefix

func (op RMIscalar) RegRegImm8(text *code.Buf, t wa.Type, r, r2 reg.R, val int8) {
	var o output
	o.byte(0x66)
	o.byte(0x0f)
	o.byte(byte(op))
	o.byte(typeRMISizeCode(t))
	o.mod(ModReg, regRO(r), regRM(r2))
	o.int8(val)
	o.copy(text.Extend(o.len()))
}

// D

type Db byte    // opcode byte
type Dd byte    // opcode byte
type D2d uint16 // two opcode bytes
type D12 uint32 // combination

func (ops D12) Addr(text *code.Buf, addr int32) {
	const (
		insnSize8  = 2
		insnSize32 = 6
	)

	var o output

	if addr != 0 {
		disp8 := addrDisp(text.Addr, insnSize8, addr)
		if uint32(disp8+128) <= 255 {
			o.byte(uint8(ops))
			o.int8(int8(disp8))
			o.copy(text.Extend(o.len()))
			return
		}
	}

	disp32 := addrDisp(text.Addr, insnSize32, addr)
	o.word(uint16(ops >> 16))
	o.int32(disp32)
	o.copy(text.Extend(o.len()))
}

func (op Db) Addr8(text *code.Buf, addr int32) {
	const insnSize = 2

	disp := addrDisp(text.Addr, insnSize, addr)

	var o output
	o.byte(byte(op))
	o.int8(int8(disp))
	o.copy(text.Extend(o.len()))
}

func (ops D12) Stub(text *code.Buf, near bool) {
	const (
		insnSize8  = 2
		insnSize32 = 6
	)

	if near {
		var o output
		o.byte(uint8(ops))
		o.int8(-insnSize8) // infinite loop as placeholder
		o.copy(text.Extend(o.len()))
	} else {
		var o output
		o.word(uint16(ops >> 16))
		o.int32(-insnSize32) // infinite loop as placeholder
		o.copy(text.Extend(o.len()))
	}
}

func (op Db) Stub8(text *code.Buf) {
	const insnSize = 2

	disp := -insnSize // infinite loop as placeholder

	var o output
	o.byte(byte(op))
	o.int8(int8(disp))
	o.copy(text.Extend(o.len()))
}

func (op Dd) Addr32(text *code.Buf, addr int32) {
	const insnSize = 5

	disp := addrDisp(text.Addr, insnSize, addr)

	var o output
	o.byte(byte(op))
	o.int32(disp)
	o.copy(text.Extend(o.len()))
}

func (op D2d) Addr32(text *code.Buf, addr int32) {
	const insnSize = 6

	disp := addrDisp(text.Addr, insnSize, addr)

	var o output
	o.word(uint16(op))
	o.int32(disp)
	o.copy(text.Extend(o.len()))
}

func (op Dd) Stub32(text *code.Buf) {
	const insnSize = 5

	var o output
	o.byte(byte(op))
	o.int32(-insnSize) // infinite loop as placeholder
	o.copy(text.Extend(o.len()))
}

func (op D2d) Stub32(text *code.Buf) {
	const insnSize = 6

	var o output
	o.word(uint16(op))
	o.int32(-insnSize) // infinite loop as placeholder
	o.copy(text.Extend(o.len()))
}

func (op Dd) MissingFunction(text *code.Buf) {
	const insnSize = 5

	var o output

	// Position of disp must be aligned
	if n := (text.Addr + insnSize - 4) & 3; n > 0 {
		size := 4 - n
		copy(o.buf[:size], nops[size][:size])
		o.offset = uint8(size)
	}

	siteAddr := text.Addr + int32(o.offset) + insnSize
	disp := -siteAddr // MissingFunction trap

	o.byte(byte(op))
	o.int32(disp)
	o.copy(text.Extend(o.len()))
}
