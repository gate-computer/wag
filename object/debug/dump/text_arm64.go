// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo

package dump

import (
	"fmt"
	"strings"

	"github.com/bnagy/gapstone"
	"github.com/tsavola/wag/trap"
)

const (
	csArch   = gapstone.CS_ARCH_ARM64
	csMode   = gapstone.CS_MODE_LITTLE_ENDIAN
	csSyntax = gapstone.CS_OPT_SYNTAX_DEFAULT
	padInsn  = gapstone.ARM64_INS_BRK
)

func rewriteText(insns []gapstone.Instruction, targets map[uint]string, textAddr uintptr, firstFuncAddr uint) {
	sequence := 0
	skipTrapInsn := false

	for i := range insns {
		insn := &insns[i]

		if insn.Address < firstFuncAddr {
			if skipTrapInsn {
				skipTrapInsn = false
				continue
			}

			if insn.Mnemonic == "sub" && strings.HasPrefix(insn.OpStr, "x30, x30, #0x") {
				targets[insn.Address] = "trap.call_stack_exhausted"
				skipTrapInsn = true
			}

			if insn.Mnemonic == "movz" && strings.HasPrefix(insn.OpStr, "x0, #0x") {
				var n uint
				fmt.Sscanf(insn.OpStr, "x0, #0x%x", &n)
				if id := trap.ID(n); id < trap.NumTraps {
					targets[insn.Address] = "trap." + strings.Replace(id.String(), " ", "_", -1)
				}
			}
		}
	}

	for i := range insns {
		insn := &insns[i]

		if insn.Mnemonic == "b" || insn.Mnemonic == "bl" || strings.HasPrefix(insn.Mnemonic, "b.") {
			var addr uint
			if n, err := fmt.Sscanf(insn.OpStr, "#0x%x", &addr); err != nil {
				panic(err)
			} else if n != 1 {
				panic(n)
			}

			name, found := targets[addr]
			if !found {
				name = fmt.Sprintf(".%x", sequence%0x10000)
				sequence++

				if addr < insn.Address {
					name += "\t\t\t; back"
				}

				targets[addr] = name
			}

			insn.OpStr = name
		}
	}
}
