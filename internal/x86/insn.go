// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
)

type prefix interface {
	put(code gen.Buffer, t abi.Type, ro, index, rmOrBase byte)
}

type constPrefix []byte

func (bytes constPrefix) put(code gen.Buffer, t abi.Type, ro, index, rmOrBase byte) {
	code.PutBytes(bytes)
}

type multiPrefix []prefix

func (array multiPrefix) put(code gen.Buffer, t abi.Type, ro, index, rmOrBase byte) {
	for _, p := range array {
		p.put(code, t, ro, index, rmOrBase)
	}
}

const (
	Rex  = (1 << 6)
	RexW = Rex | (1 << 3)
	RexR = Rex | (1 << 2)
	RexX = Rex | (1 << 1)
	RexB = Rex | (1 << 0)
)

func putRex(code gen.Buffer, rex, ro, index, rmOrBase byte) {
	if ro >= 8 {
		rex |= RexR
	}
	if index >= 8 {
		rex |= RexX
	}
	if rmOrBase >= 8 {
		rex |= RexB
	}

	if rex != 0 {
		code.PutByte(rex)
	}
}

func putRexSize(code gen.Buffer, t abi.Type, ro, index, rmOrBase byte) {
	var rex byte

	switch t.Size() {
	case abi.Size32:

	case abi.Size64:
		rex |= RexW

	default:
		panic(t)
	}

	putRex(code, rex, ro, index, rmOrBase)
}

type mod byte

const (
	ModMem       = mod(0)
	ModMemDisp8  = mod((0 << 7) | (1 << 6))
	ModMemDisp32 = mod((1 << 7) | (0 << 6))
	ModReg       = mod((1 << 7) | (1 << 6))
)

func dispMod(t abi.Type, baseReg regs.R, offset int32) mod {
	switch {
	case offset == 0 && (baseReg&7) != 0x5: // rbp and r13 need displacement
		return ModMem

	case offset >= -0x80 && offset < 0x80:
		return ModMemDisp8

	default:
		return ModMemDisp32
	}
}

func putMod(code gen.Buffer, mod mod, ro, rm byte) {
	code.PutByte(byte(mod) | ((ro & 7) << 3) | (rm & 7))
}

func putDisp(code gen.Buffer, mod mod, offset int32) {
	switch mod {
	case ModMemDisp8:
		gen.PutInt8(code, int8(offset))

	case ModMemDisp32:
		gen.PutInt32(code, offset)
	}
}

const (
	MemSIB    = byte((1 << 2))
	MemDisp32 = byte((1 << 2) | (1 << 0))
)

const (
	NoIndex = regs.R((1 << 2))
	NoBase  = regs.R((1 << 2) | (1 << 0))
)

func putSib(code gen.Buffer, scale byte, index, base regs.R) {
	if scale >= 4 {
		panic("scale factor out of bounds")
	}

	code.PutByte((scale << 6) | (byte(index&7) << 3) | byte(base&7))
}

//
type insnConst []byte

func (opcode insnConst) op(code gen.Buffer) {
	code.PutBytes(opcode)
}

//
type insnO struct {
	opbase byte
}

func (i insnO) op(code gen.Buffer, reg regs.R) {
	if reg >= 8 {
		panic("register not supported by instruction")
	}

	code.PutByte(i.opbase + byte(reg))
}

//
type insnI []byte

func (opcode insnI) op8(code gen.Buffer, value int8) {
	code.PutBytes(opcode)
	gen.PutInt8(code, value)
}

func (opcode insnI) op32(code gen.Buffer, value int32) {
	code.PutBytes(opcode)
	gen.PutInt32(code, value)
}

//
type insnAddr8 []byte

func (opcode insnAddr8) size() int32 {
	return int32(len(opcode)) + 1
}

func (opcode insnAddr8) op(code gen.Buffer, addr int32) (ok bool) {
	insnSize := int32(len(opcode)) + 1
	siteAddr := code.Pos() + insnSize
	offset := addr - siteAddr

	if offset >= -0x80 && offset < 0x80 {
		code.PutBytes(opcode)
		gen.PutInt8(code, int8(offset))
		ok = true
	}
	return
}

func (i insnAddr8) opStub(code gen.Buffer) {
	i.op(code, code.Pos()) // infinite loop as placeholder
}

//
type insnAddr32 []byte

func (opcode insnAddr32) size() int32 {
	return int32(len(opcode)) + 4
}

func (i insnAddr32) op(code gen.Buffer, addr int32) {
	var offset int32
	if addr != 0 {
		siteAddr := code.Pos() + i.size()
		offset = addr - siteAddr
	} else {
		offset = -i.size() // infinite loop as placeholder
	}
	i.put(code, offset)
}

func (i insnAddr32) opMissingFunction(code gen.Buffer) {
	siteAddr := code.Pos() + i.size()
	i.put(code, -siteAddr)
}

func (opcode insnAddr32) put(code gen.Buffer, offset int32) {
	code.PutBytes(opcode)
	gen.PutInt32(code, offset)
}

//
type insnAddr struct {
	rel8  insnAddr8
	rel32 insnAddr32
}

func (i insnAddr) op(code gen.Buffer, addr int32) {
	var ok bool
	if addr != 0 {
		ok = i.rel8.op(code, addr)
	}
	if !ok {
		i.rel32.op(code, addr)
	}
}

//
type insnRex []byte

func (opcode insnRex) op(code gen.Buffer, t abi.Type) {
	putRexSize(code, t, 0, 0, 0)
	code.PutBytes(opcode)
}

//
type insnRexOM struct {
	opcode []byte
	ro     byte
}

func (i insnRexOM) opReg(code gen.Buffer, reg regs.R) {
	putRex(code, 0, 0, 0, byte(reg))
	code.PutBytes(i.opcode)
	putMod(code, ModReg, i.ro, byte(reg))
}

//
type insnRexO struct {
	opbase byte
}

func (i insnRexO) op(code gen.Buffer, t abi.Type, reg regs.R) {
	putRexSize(code, t, 0, 0, byte(reg))
	code.PutByte(i.opbase + (byte(reg) & 7))
}

//
type insnRexOI struct {
	opbase byte
}

func (i insnRexOI) op32(code gen.Buffer, t abi.Type, reg regs.R, value uint32) {
	putRexSize(code, t, 0, 0, byte(reg))
	code.PutByte(i.opbase + (byte(reg) & 7))
	gen.PutInt32(code, int32(value))
}

func (i insnRexOI) op64(code gen.Buffer, t abi.Type, reg regs.R, value int64) {
	putRexSize(code, t, 0, 0, byte(reg))
	code.PutByte(i.opbase + (byte(reg) & 7))
	gen.PutInt64(code, value)
}

//
type insnRexM struct {
	opcode []byte
	ro     byte
}

func (i insnRexM) opReg(code gen.Buffer, t abi.Type, reg regs.R) {
	putRexSize(code, t, 0, 0, byte(reg))
	code.PutBytes(i.opcode)
	putMod(code, ModReg, i.ro, byte(reg))
}

func (i insnRexM) opIndirect(code gen.Buffer, t abi.Type, reg regs.R, disp int32) {
	mod := dispMod(t, reg, disp)

	putRexSize(code, t, 0, 0, byte(reg))
	code.PutBytes(i.opcode)

	if reg != 12 {
		putMod(code, mod, i.ro, byte(reg))
	} else {
		putMod(code, mod, i.ro, MemSIB)
		putSib(code, 0, NoIndex, reg)
	}

	putDisp(code, mod, disp)
}

func (i insnRexM) opStack(code gen.Buffer, t abi.Type, disp int32) {
	mod := dispMod(t, RegStackPtr, disp)

	putRexSize(code, t, 0, 0, 0)
	code.PutBytes(i.opcode)
	putMod(code, mod, i.ro, MemSIB)
	putSib(code, 0, RegStackPtr, RegStackPtr)
	putDisp(code, mod, disp)
}

var (
	noRexMInsn = insnRexM{nil, 0}
)

//
type insnPrefix struct {
	prefix   prefix
	opcodeRM []byte
	opcodeMR []byte
}

func (i insnPrefix) opFromReg(code gen.Buffer, t abi.Type, target, source regs.R) {
	putPrefixRegInsn(code, i.prefix, t, i.opcodeRM, byte(target), byte(source))
}

func (i insnPrefix) opFromAddr(code gen.Buffer, t abi.Type, target regs.R, scale uint8, index regs.R, addr int32) {
	putPrefixAddrInsn(code, i.prefix, t, i.opcodeRM, target, scale, index, addr)
}

func (i insnPrefix) opFromIndirect(code gen.Buffer, t abi.Type, target regs.R, scale uint8, index, base regs.R, disp int32) {
	putPrefixIndirectInsn(code, i.prefix, t, i.opcodeRM, target, scale, index, base, disp)
}

func (i insnPrefix) opFromStack(code gen.Buffer, t abi.Type, target regs.R, disp int32) {
	putPrefixStackInsn(code, i.prefix, t, i.opcodeRM, target, disp)
}

func (i insnPrefix) opToReg(code gen.Buffer, t abi.Type, target, source regs.R) {
	putPrefixRegInsn(code, i.prefix, t, i.opcodeMR, byte(source), byte(target))
}

func (i insnPrefix) opToAddr(code gen.Buffer, t abi.Type, source regs.R, scale uint8, index regs.R, addr int32) {
	putPrefixAddrInsn(code, i.prefix, t, i.opcodeMR, source, scale, index, addr)
}

func (i insnPrefix) opToIndirect(code gen.Buffer, t abi.Type, target regs.R, scale uint8, index, base regs.R, disp int32) {
	putPrefixIndirectInsn(code, i.prefix, t, i.opcodeMR, target, scale, index, base, disp)
}

func (i insnPrefix) opToStack(code gen.Buffer, t abi.Type, source regs.R, disp int32) {
	putPrefixStackInsn(code, i.prefix, t, i.opcodeMR, source, disp)
}

func putPrefixRegInsn(code gen.Buffer, p prefix, t abi.Type, opcode []byte, ro, rm byte) {
	if opcode == nil {
		panic("instruction not supported")
	}

	p.put(code, t, ro, 0, rm)
	code.PutBytes(opcode)
	putMod(code, ModReg, ro, rm)
}

func putPrefixAddrInsn(code gen.Buffer, p prefix, t abi.Type, opcode []byte, reg regs.R, scale uint8, index regs.R, addr int32) {
	if opcode == nil {
		panic("instruction not supported")
	}

	p.put(code, t, byte(reg), 0, 0)
	code.PutBytes(opcode)
	putMod(code, ModMem, byte(reg), MemSIB)
	putSib(code, scale, index, NoBase)
	gen.PutInt32(code, addr)
}

func putPrefixIndirectInsn(code gen.Buffer, p prefix, t abi.Type, opcode []byte, reg regs.R, scale uint8, index, base regs.R, disp int32) {
	if opcode == nil {
		panic("instruction not supported")
	}

	mod := dispMod(t, base, disp)

	p.put(code, t, byte(reg), byte(index), byte(base))
	code.PutBytes(opcode)

	if scale == 0 && index == NoIndex && base != 12 {
		putMod(code, mod, byte(reg), byte(base))
	} else {
		putMod(code, mod, byte(reg), MemSIB)
		putSib(code, scale, index, base)
	}

	putDisp(code, mod, disp)
}

func putPrefixStackInsn(code gen.Buffer, p prefix, t abi.Type, opcode []byte, reg regs.R, disp int32) {
	mod := dispMod(t, RegStackPtr, disp)

	p.put(code, t, byte(reg), 0, 0)
	code.PutBytes(opcode)
	putMod(code, mod, byte(reg), MemSIB)
	putSib(code, 0, RegStackPtr, RegStackPtr)
	putDisp(code, mod, disp)
}

//
type insnPrefixRexRM struct {
	prefix prefix
	opcode []byte
}

func (i insnPrefixRexRM) opReg(code gen.Buffer, floatType, intType abi.Type, target, source regs.R) {
	i.prefix.put(code, floatType, 0, 0, 0)
	putRexSize(code, intType, byte(target), 0, byte(source))
	code.PutBytes(i.opcode)
	putMod(code, ModReg, byte(target), byte(source))
}

//
type insnPrefixMI struct {
	prefix   prefix
	opcode8  byte
	opcode16 byte
	opcode32 byte
	ro       byte
}

func (i insnPrefixMI) opImm(code gen.Buffer, t abi.Type, reg regs.R, value int32) {
	opcode := i.immOpcode(value)

	i.prefix.put(code, t, 0, 0, byte(reg))
	code.PutByte(opcode)
	putMod(code, ModReg, i.ro, byte(reg))
	i.putImm(code, opcode, value)
}

func (i insnPrefixMI) opImm8(code gen.Buffer, t abi.Type, reg regs.R, value uint8) {
	i.prefix.put(code, t, 0, 0, byte(reg))
	code.PutByte(i.opcode8)
	putMod(code, ModReg, i.ro, byte(reg))
	code.PutByte(value)
}

func (i insnPrefixMI) opImmToIndirect(code gen.Buffer, t abi.Type, scale uint8, index, base regs.R, disp, value int32) {
	mod := dispMod(t, base, disp)
	opcode := i.immOpcode(value)

	i.prefix.put(code, t, 0, byte(index), byte(base))
	code.PutByte(opcode)

	if scale == 0 && index == NoIndex && base != 12 {
		putMod(code, mod, i.ro, byte(base))
	} else {
		putMod(code, mod, i.ro, MemSIB)
		putSib(code, scale, index, base)
	}

	putDisp(code, mod, disp)
	i.putImm(code, opcode, value)
}

func (i insnPrefixMI) opImmToStack(code gen.Buffer, t abi.Type, disp, value int32) {
	mod := dispMod(t, RegStackPtr, disp)
	opcode := i.immOpcode(value)

	i.prefix.put(code, t, 0, 0, 0)
	code.PutByte(opcode)
	putMod(code, mod, i.ro, MemSIB)
	putSib(code, 0, RegStackPtr, RegStackPtr)
	putDisp(code, mod, disp)
	i.putImm(code, opcode, value)
}

func (i insnPrefixMI) immOpcode(value int32) byte {
	switch {
	case i.opcode8 != 0 && value >= -0x80 && value < 0x80:
		return i.opcode8

	case i.opcode16 != 0 && value >= -0x8000 && value < 0x8000:
		return i.opcode16

	case i.opcode32 != 0:
		return i.opcode32

	default:
		panic("immediate value out of range")
	}
}

func (i insnPrefixMI) putImm(code gen.Buffer, opcode byte, value int32) {
	switch opcode {
	case i.opcode8:
		gen.PutInt8(code, int8(value))

	case i.opcode16:
		gen.PutInt16(code, int16(value))

	default: // i.opcode32
		gen.PutInt32(code, value)
	}
}

var (
	noPrefixMIInsn = insnPrefixMI{nil, 0, 0, 0, 0}
)

//
type insnSuffixRMI struct {
	opcode []byte
	suffix prefix
}

func (i insnSuffixRMI) opReg(code gen.Buffer, t abi.Type, target, source regs.R, value int8) {
	code.PutBytes(i.opcode)
	i.suffix.put(code, t, byte(target), 0, byte(source))
	putMod(code, ModReg, byte(target), byte(source))
	gen.PutInt8(code, value)
}

//
type binaryInsn struct {
	insnPrefix
	insnPrefixMI
}

//
type pushPopInsn struct {
	regLow insnO
	regAny insnRexM
}

func (i pushPopInsn) op(code gen.Buffer, reg regs.R) {
	if reg < 8 {
		i.regLow.op(code, reg)
	} else {
		i.regAny.opReg(code, abi.I32, reg)
	}
}

//
type xchgInsn struct {
	r0 insnRexO
	insnPrefix
}

func (i xchgInsn) opFromReg(code gen.Buffer, t abi.Type, a, b regs.R) {
	switch {
	case a == regs.R(0):
		i.r0.op(code, t, b)

	case b == regs.R(0):
		i.r0.op(code, t, a)

	default:
		i.insnPrefix.opFromReg(code, t, a, b)
	}
}

//
type shiftImmInsn struct {
	one insnRexM
	any insnPrefixMI
}

func (i shiftImmInsn) defined() bool {
	return i.one.opcode != nil
}

func (i shiftImmInsn) op(code gen.Buffer, t abi.Type, reg regs.R, value uint8) {
	if value == 1 {
		i.one.opReg(code, t, reg)
	} else {
		i.any.opImm8(code, t, reg, value)
	}
}

var (
	noShiftImmInsn = shiftImmInsn{noRexMInsn, noPrefixMIInsn}
)

//
type movImmInsn struct {
	imm32 insnPrefixMI
	imm   insnRexOI
}

func (i movImmInsn) op(code gen.Buffer, t abi.Type, reg regs.R, value int64) {
	switch {
	case value >= -0x80000000 && value < 0x80000000:
		i.imm32.opImm(code, t, reg, int32(value))

	case t.Size() == abi.Size64 && value >= 0 && value < 0x100000000:
		i.imm.op32(code, abi.I32, reg, uint32(value))

	default:
		i.imm.op64(code, t, reg, value)
	}
}
