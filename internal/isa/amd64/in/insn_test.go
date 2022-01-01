// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build cgo
// +build cgo

package in

import (
	"fmt"
	"testing"

	"gate.computer/wag/internal/code"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/wa"
)

var (
	intTypes = []wa.Type{wa.I32, wa.I64}

	allRegs   = []reg.R{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	indexRegs = []reg.R{0, 1, 2, 3 /* skip stack */, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	baseRegs  = []BaseReg{BaseScratch, BaseZero, BaseMemory, BaseText}

	regNamesI8  = []string{"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"}
	regNamesI16 = []string{"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"}
	regNamesI32 = []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"}
	regNamesI64 = []string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}

	typeRegNames = map[wa.Type][]string{
		wa.I32: regNamesI32,
		wa.I64: regNamesI64,
	}

	memSizes = map[wa.Type]string{
		wa.I32: "dword",
		wa.I64: "qword",
	}

	scales = []struct {
		Scale
		string
	}{
		{Scale0, ""},
		{Scale1, "*2"},
		{Scale2, "*4"},
		{Scale3, "*8"},
	}
)

func TestInsnNP(test *testing.T) {
	testEncode(test, "pause", "", func(text *code.Buf) { PAUSE.Simple(text) })
	testEncode(test, "cdq", "", func(text *code.Buf) { CDQ.Type(text, wa.I32) })
	testEncode(test, "cqo", "", func(text *code.Buf) { CDQ.Type(text, wa.I64) })
	testEncode(test, "ret", "", func(text *code.Buf) { RET.Simple(text) })
}

func TestInsnO(test *testing.T) {
	for _, i := range []struct {
		mn string
		op O
	}{
		{"push", PUSHo},
		{"pop", POPo},
	} {
		testEncode(test, i.mn, "rax", func(text *code.Buf) { i.op.RegResult(text) })
		testEncode(test, i.mn, "rcx", func(text *code.Buf) { i.op.RegScratch(text) })
		testEncode(test, i.mn, "rdx", func(text *code.Buf) { i.op.RegZero(text) })
	}
}

func TestInsnM(test *testing.T) {
	// Test Reg with variable operand size
	for _, i := range []struct {
		mn     string
		op     M
		suffix string
	}{
		{"rol", ROL, ", cl"},
		{"ror", ROR, ", cl"},
		{"shl", SHL, ", cl"},
		{"shr", SHR, ", cl"},
		{"sar", SAR, ", cl"},
		{"neg", NEG, ""},
		{"div", DIV, ""},
		{"idiv", IDIV, ""},
		{"inc", INC, ""},
		{"dec", DEC, ""},
	} {
		for _, t := range intTypes {
			for _, r := range allRegs {
				testEncode(test, i.mn, typeRegNames[t][r]+i.suffix, func(text *code.Buf) {
					i.op.Reg(text, t, r)
				})
			}
		}
	}

	// Test Reg with fixed operand size
	for _, i := range []struct {
		mn string
		op M
	}{
		{"pop", POP},
		{"push", PUSH},
	} {
		for _, r := range allRegs {
			testEncode(test, i.mn, regNamesI64[r], func(text *code.Buf) {
				i.op.Reg(text, OneSize, r)
			})
		}
	}

	// Test SimpleReg
	for _, i := range []struct {
		mn string
		op Mex2
	}{
		{"setb", SETB},
		{"setae", SETAE},
		{"sete", SETE},
		{"setne", SETNE},
		{"setbe", SETBE},
		{"seta", SETA},
		{"sets", SETS},
		{"setp", SETP},
		{"setl", SETL},
		{"setge", SETGE},
		{"setle", SETLE},
		{"setg", SETG},
	} {
		for _, r := range allRegs {
			testEncode(test, i.mn, regNamesI8[r], func(text *code.Buf) {
				i.op.OneSizeReg(text, r)
			})
		}
	}
}

func TestInsnRMint(test *testing.T) {
	for _, i := range []struct {
		mn          string
		op          interface{}
		mr          bool
		skipRegReg  bool
		types       []wa.Type
		op2RegNames []string
		memSize     string
		commutative bool
	}{
		{mn: "add", op: ADD},
		{mn: "or", op: OR},
		{mn: "and", op: AND},
		{mn: "sub", op: SUB},
		{mn: "xor", op: XOR},
		{mn: "cmp", op: CMP},
		{mn: "cmovb", op: CMOVB},
		{mn: "cmovae", op: CMOVAE},
		{mn: "cmove", op: CMOVE},
		{mn: "cmovne", op: CMOVNE},
		{mn: "cmovbe", op: CMOVBE},
		{mn: "cmova", op: CMOVA},
		{mn: "cmovs", op: CMOVS},
		{mn: "cmovp", op: CMOVP},
		{mn: "cmovl", op: CMOVL},
		{mn: "cmovge", op: CMOVGE},
		{mn: "cmovle", op: CMOVLE},
		{mn: "cmovg", op: CMOVG},
		{mn: "movsxd", op: MOVSXD,
			types:       []wa.Type{wa.I64},
			op2RegNames: regNamesI32,
			memSize:     "dword"},
		{mn: "test", op: TEST, mr: true, commutative: true},
		{mn: "mov", op: MOVmr, mr: true, skipRegReg: true},
		{mn: "mov", op: MOV},
		{mn: "lea", op: LEA, skipRegReg: true},
		{mn: "imul", op: IMUL},
		{mn: "movzx", op: MOVZX8, memSize: "byte", skipRegReg: true},
		{mn: "movzx", op: MOVZX16, memSize: "word", skipRegReg: true},
		{mn: "popcnt", op: POPCNT},
		{mn: "tzcnt", op: TZCNT},
		{mn: "lzcnt", op: LZCNT},
		{mn: "bsf", op: BSF},
		{mn: "bsr", op: BSR},
		{mn: "movsx", op: MOVSX8, memSize: "byte", skipRegReg: true},
		{mn: "movsx", op: MOVSX16, memSize: "word", skipRegReg: true},
	} {
		types := i.types
		if types == nil {
			types = intTypes
		}

		for _, t := range types {
			ms := i.memSize
			if ms == "" {
				ms = memSizes[t]
			}

			for _, r := range allRegs {
				rn := typeRegNames[t][r]

				// Test RegReg
				if op, ok := i.op.(rmRegReg); ok && !i.skipRegReg {
					rns2 := i.op2RegNames
					if rns2 == nil {
						rns2 = typeRegNames[t]
					}

					for _, r2 := range allRegs {
						opStrs := []string{opStr(rn, rns2[r2])}
						if i.commutative {
							opStrs = append(opStrs, opStr(rns2[r2], rn))
						}

						testEncodeAny(test, i.mn, opStrs, func(text *code.Buf) {
							op.RegReg(text, t, r, r2)
						})
					}
				}

				// Test RegMemDisp
				if op, ok := i.op.(rmRegMemDisp); ok {
					for _, base := range baseRegs {
						for disp, dispStr := range testDisp32 {
							opStr := opStrSwapIf(i.mr, rn, fmt.Sprintf("%s ptr [%s%s]", ms, regNamesI64[base], dispStr))

							testEncode(test, i.mn, opStr, func(text *code.Buf) {
								op.RegMemDisp(text, t, r, base, disp)
							})
						}
					}
				}

				// Test RegMemIndexDisp
				if op, ok := i.op.(rmRegMemIndexDisp); ok {
					for _, base := range baseRegs {
						for _, index := range indexRegs {
							for _, s := range scales {
								for disp, dispStr := range testDisp32 {
									opStr := opStrSwapIf(i.mr, rn, fmt.Sprintf("%s ptr [%s + %s%s%s]", ms, regNamesI64[base], regNamesI64[index], s.string, dispStr))

									testEncode(test, i.mn, opStr, func(text *code.Buf) {
										op.RegMemIndexDisp(text, t, r, base, index, s.Scale, disp)
									})
								}
							}
						}
					}
				}

				// Test RegStack
				if op, ok := i.op.(rmRegStack); ok {
					opStr := opStrSwapIf(i.mr, rn, fmt.Sprintf("%s ptr [rsp]", ms))

					testEncode(test, i.mn, opStr, func(text *code.Buf) {
						op.RegStack(text, t, r)
					})
				}

				// Test RegStackDisp
				if op, ok := i.op.(rmRegStackDisp); ok {
					for disp, dispStr := range testDisp32 {
						opStr := opStrSwapIf(i.mr, rn, fmt.Sprintf("%s ptr [rsp%s]", ms, dispStr))

						testEncode(test, i.mn, opStr, func(text *code.Buf) {
							op.RegStackDisp(text, t, r, disp)
						})
					}
				}

				// Test RegStackDisp8
				if op, ok := i.op.(rmRegStackDisp8); ok {
					for disp, dispStr := range testDisp8 {
						opStr := opStrSwapIf(i.mr, rn, fmt.Sprintf("%s ptr [rsp%s]", ms, dispStr))

						testEncode(test, i.mn, opStr, func(text *code.Buf) {
							op.RegStackDisp8(text, t, r, disp)
						})
					}
				}

				// Test RegStackStub32
				if op, ok := i.op.(rmRegStackStub32); ok {
					opStr := opStrSwapIf(i.mr, rn, fmt.Sprintf("%s ptr [rsp - 0x80000000]", ms))

					testEncode(test, i.mn, opStr, func(text *code.Buf) {
						op.RegStackStub32(text, t, r)
					})
				}
			}
		}
	}

	// Test RegRegStackLimit
	for _, i := range []struct {
		mn string
		op RMdata8
	}{
		{"test", TEST8},
	} {
		testEncode(test, i.mn, "bl, bl", func(text *code.Buf) {
			i.op.RegRegStackLimit(text)
		})
	}

	for _, ignoredType := range intTypes {
		for _, r := range allRegs {
			for _, base := range baseRegs {
				for disp, dispStr := range testDisp32 {
					// Test RegMemDisp with 8-bit operand size
					opStr := fmt.Sprintf("byte ptr [%s%s], %s", regNamesI64[base], dispStr, regNamesI8[r])

					testEncode(test, "mov", opStr, func(text *code.Buf) {
						MOV8mr.RegMemDisp(text, ignoredType, r, base, disp)
					})

					// Test RegMemDisp with 16-bit operand size
					opStr = fmt.Sprintf("word ptr [%s%s], %s", regNamesI64[base], dispStr, regNamesI16[r])

					testEncode(test, "mov", opStr, func(text *code.Buf) {
						MOV16mr.RegMemDisp(text, ignoredType, r, base, disp)
					})
				}
			}
		}
	}
}

func TestInsnI(test *testing.T) {
	for _, val := range testImm32 {
		testEncodeImm(test, "push", "IMM", optimalImm(val), func(text *code.Buf) {
			PUSHi.Imm(text, val)
		})
	}
}

func TestInsnOI(test *testing.T) {
	for _, r := range allRegs {
		for _, val := range testImm64 {
			testEncodeImm(test, "movabs", regNamesI64[r]+", IMM", val, func(text *code.Buf) {
				MOV64i.RegImm64(text, r, val)
			})
		}
	}
}

func TestInsnMI(test *testing.T) {
	for _, i := range []struct {
		mn        string
		op        MI
		skipImm8  bool
		skipImm32 bool
	}{
		{mn: "add", op: ADDi},
		{mn: "or", op: ORi},
		{mn: "and", op: ANDi},
		{mn: "sub", op: SUBi},
		{mn: "xor", op: XORi},
		{mn: "cmp", op: CMPi},
		{mn: "rol", op: ROLi, skipImm32: true},
		{mn: "ror", op: RORi, skipImm32: true},
		{mn: "shl", op: SHLi, skipImm32: true},
		{mn: "shr", op: SHRi, skipImm32: true},
		{mn: "sar", op: SARi, skipImm32: true},
		{mn: "mov", op: MOVi, skipImm8: true},
	} {
		for _, t := range intTypes {
			for _, r := range allRegs {
				opStr := typeRegNames[t][r] + ", IMM"

				// Test RegImm
				if !i.skipImm8 && !i.skipImm32 {
					for _, val := range testImm32 {
						testEncodeImm(test, i.mn, opStr, optimalImm(val), func(text *code.Buf) {
							i.op.RegImm(text, t, r, val)
						})
					}
				}

				// Test RegImm8
				if !i.skipImm8 {
					for _, val := range testImm8 {
						testEncodeImm(test, i.mn, opStr, val, func(text *code.Buf) {
							i.op.RegImm8(text, t, r, val)
						})
					}
				}

				// Test RegImm32
				if !i.skipImm32 {
					for _, val := range testImm32 {
						testEncodeImm(test, i.mn, opStr, val, func(text *code.Buf) {
							i.op.RegImm32(text, t, r, val)
						})
					}
				}
			}

			if !i.skipImm8 {
				// Test StackImm8
				opStr := fmt.Sprintf("%s ptr [rsp], IMM", memSizes[t])

				for _, val := range testImm8 {
					testEncodeImm(test, i.mn, opStr, val, func(text *code.Buf) {
						i.op.StackImm8(text, t, val)
					})
				}
			}

			if !i.skipImm32 {
				for disp, dispStr := range testDisp32 {
					// Test StackDispImm32
					opStr := fmt.Sprintf("%s ptr [rsp%s], IMM", memSizes[t], dispStr)

					for _, val := range testImm32 {
						testEncodeImm(test, i.mn, opStr, val, func(text *code.Buf) {
							i.op.StackDispImm32(text, t, disp, val)
						})
					}
				}
			}
		}
	}

	for _, t := range intTypes {
		for _, base := range baseRegs {
			for disp, dispStr := range testDisp32 {
				// Test MemDispImm with 8-bit width
				opStr := fmt.Sprintf("byte ptr [%s%s], IMM", regNamesI64[base], dispStr)

				for _, val := range testImm8 {
					testEncodeImm(test, "mov", opStr, val, func(text *code.Buf) {
						MOV8i.MemDispImm(text, t, base, disp, int64(val))
					})
				}

				// Test MemDispImm with 16-bit width
				opStr = fmt.Sprintf("word ptr [%s%s], IMM", regNamesI64[base], dispStr)

				for _, val := range testImm16 {
					testEncodeImm(test, "mov", opStr, val, func(text *code.Buf) {
						MOV16i.MemDispImm(text, t, base, disp, int64(val))
					})
				}

				// Test MemDispImm with 32/64-bit width
				opStr = fmt.Sprintf("%s ptr [%s%s], IMM", memSizes[t], regNamesI64[base], dispStr)

				for _, val := range testImm16 {
					testEncodeImm(test, "mov", opStr, val, func(text *code.Buf) {
						MOV32i.MemDispImm(text, t, base, disp, int64(val))
					})
				}
			}
		}
	}
}

func TestInsnRMI(test *testing.T) {
	for _, t := range intTypes {
		for _, r := range allRegs {
			for _, r2 := range allRegs {
				opStr := typeRegNames[t][r] + ", " + typeRegNames[t][r2] + ", IMM"

				for _, val := range testImm32 {
					testEncodeImm(test, "imul", opStr, val, func(text *code.Buf) {
						IMULi.RegRegImm(text, t, r, r2, val)
					})
				}
			}
		}
	}
}

// TODO: float and D encoding tests
