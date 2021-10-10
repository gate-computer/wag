// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo,amd64,!wagarm64 cgo,wagamd64

package dump

import (
	"fmt"
	"strconv"
	"strings"

	"gate.computer/wag/internal/isa/x86/nonabi"
	"gate.computer/wag/object/abi"
	"gate.computer/wag/trap"
	"github.com/knightsc/gapstone"
)

const (
	csArch   = gapstone.CS_ARCH_X86
	csMode   = gapstone.CS_MODE_64
	csSyntax = gapstone.CS_OPT_SYNTAX_ATT
	padInsn  = gapstone.X86_INS_INT3
)

func rewriteText(insns []gapstone.Instruction, targets map[uint]string, textAddr uintptr, firstFuncAddr uint) {
	targets[uint(textAddr)+abi.TextAddrNoFunction] = "trap.no_function"
	targets[uint(textAddr)+nonabi.TextAddrRetpoline] = "retpoline"
	targets[uint(textAddr)+nonabi.TextAddrRetpolineSetup] = "retpoline.setup"

	sequence := 0
	skipTrapInsn := false

	for i := range insns {
		insn := &insns[i]

		insn.OpStr = strings.Replace(insn.OpStr, "%al", "resultb", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%ah", "resultw", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%eax", "result", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%rax", "result", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%cl", "scratchb", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%ch", "scratchw", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%ecx", "scratch", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%rcx", "scratch", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%dl", "zerob", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%dh", "zerow", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%edx", "zero", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%rdx", "zero", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%bl", "stacklimitb", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%bh", "stacklimitw", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%ebx", "stacklimit", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%rbx", "stacklimit", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%rsp", "sp", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%bpl", "r5b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%bp", "r5w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%ebp", "r5", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%rbp", "r5", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%sil", "r6b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%si", "r6w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%esi", "r6", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%rsi", "r6", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%dil", "r7b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%di", "r7w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%edi", "r7", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%rdi", "r7", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r8b", "r8b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r8w", "r8w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r8d", "r8", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r8", "r8", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r9b", "r9b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r9w", "r9w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r9d", "r9", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r9", "r9", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r10b", "r10b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r10w", "r10w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r10d", "r10", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r10", "r10", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r11b", "r11b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r11w", "r11w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r11d", "r11", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r11", "r11", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r12b", "r12b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r12w", "r12w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r12d", "r12", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r12", "r12", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r13b", "r13b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r13w", "r13w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r13d", "r13", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r13", "r13", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r14", "memory", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r15", "text", -1)

		if insn.Address < firstFuncAddr {
			if skipTrapInsn {
				skipTrapInsn = false
				continue
			}

			if insn.Mnemonic == "subq" && strings.HasPrefix(insn.OpStr, "$") && strings.HasSuffix(insn.OpStr, ", (sp)") {
				switch insn.OpStr {
				case "$0x12, (sp)":
					targets[insn.Address] = "trap.call_stack_exhausted.rewind"
					skipTrapInsn = true

				case "$8, (sp)":
					targets[insn.Address] = "trap.suspended.rewind.near"
					skipTrapInsn = true

				case "$0xc, (sp)":
					targets[insn.Address] = "trap.suspended.rewind.far"
					skipTrapInsn = true
				}
			}

			switch {
			case insn.Mnemonic == "movl":
				var n uint
				if _, err := fmt.Sscanf(insn.OpStr, "$%v, result", &n); err == nil {
					if id := trap.ID(n); id < trap.NumTraps {
						targets[insn.Address] = "trap." + strings.Replace(id.String(), " ", "_", -1)
					}
				}

			case insn.Mnemonic == "shlq" && insn.OpStr == "$0x20, result":
				targets[insn.Address] = "trap.exit"
			}
		}
	}

	for i := range insns {
		insn := &insns[i]

		switch {
		case strings.HasPrefix(insn.Mnemonic, "j") && insn.Mnemonic != "jmpq":
			fallthrough
		case insn.Mnemonic == "callq" && strings.HasPrefix(insn.OpStr, "0x"):
			fallthrough
		case insn.Mnemonic == "loop" && strings.HasPrefix(insn.OpStr, "0x"):
			addr, err := strconv.ParseUint(insn.OpStr, 0, 64)
			if err != nil {
				panic(err)
			}

			name, found := targets[uint(addr)]
			if !found {
				name = fmt.Sprintf(".%x", sequence%0x10000)
				sequence++

				if uint(addr) < insn.Address {
					name += "\t\t\t; back"
				}

				targets[uint(addr)] = name
			}

			insn.OpStr = name
		}
	}
}
