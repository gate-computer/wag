// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo,arm64,!wagamd64 cgo,wagarm64

package dump

import (
	"fmt"
	"regexp"
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

	var (
		r0  = regexp.MustCompile(`\b([wx])0\b`)
		r1  = regexp.MustCompile(`\b([wx])1\b`)
		r26 = regexp.MustCompile(`\b([wx])26\b`)
		r27 = regexp.MustCompile(`\b([wx])27\b`)
		x28 = regexp.MustCompile(`\bx28\b`)
		w28 = regexp.MustCompile(`\bw28\b`)
		r29 = regexp.MustCompile(`\b([wx])29\b`)
		r30 = regexp.MustCompile(`\b([wx])30\b`)
	)

	for i := range insns {
		insn := &insns[i]

		insn.OpStr = r0.ReplaceAllString(insn.OpStr, "${1}result")
		insn.OpStr = r1.ReplaceAllString(insn.OpStr, "${1}scratch")
		insn.OpStr = r26.ReplaceAllString(insn.OpStr, "${1}memory")
		insn.OpStr = r27.ReplaceAllString(insn.OpStr, "${1}text")
		insn.OpStr = x28.ReplaceAllString(insn.OpStr, "xstacklimit4")
		insn.OpStr = w28.ReplaceAllString(insn.OpStr, "wsuspendbit")
		insn.OpStr = r29.ReplaceAllString(insn.OpStr, "${1}fakestack")
		insn.OpStr = r30.ReplaceAllString(insn.OpStr, "${1}link")

		if insn.Address < firstFuncAddr {
			if skipTrapInsn {
				skipTrapInsn = false
				continue
			}

			if insn.Mnemonic == "sub" && strings.HasPrefix(insn.OpStr, "xlink, xlink, #0x") {
				targets[insn.Address] = "trap.call_stack_exhausted"
				skipTrapInsn = true
			}

			if insn.Mnemonic == "movz" && strings.HasPrefix(insn.OpStr, "xresult, #0x") {
				var n uint
				fmt.Sscanf(insn.OpStr, "xresult, #0x%x", &n)
				if id := trap.ID(n); id < trap.NumTraps {
					targets[insn.Address] = "trap." + strings.Replace(id.String(), " ", "_", -1)
				}
			}
		}
	}

	for i := range insns {
		insn := &insns[i]

		var prefix string
		var input string

		switch {
		case insn.Mnemonic == "b" || insn.Mnemonic == "bl" || strings.HasPrefix(insn.Mnemonic, "b."):
			input = insn.OpStr

		case strings.HasPrefix(insn.Mnemonic, "tb"):
			parts := strings.SplitN(insn.OpStr, ", ", 3)
			input = parts[2]
			parts[2] = ""
			prefix = strings.Join(parts, ", ")

		case insn.Mnemonic == "adr" || strings.HasPrefix(insn.Mnemonic, "cb"):
			parts := strings.SplitN(insn.OpStr, ", ", 2)
			input = parts[1]
			parts[1] = ""
			prefix = strings.Join(parts, ", ")

		default:
			continue
		}

		var addr uint
		if n, err := fmt.Sscanf(input, "#0x%x", &addr); err != nil {
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

		insn.OpStr = prefix + name
	}
}
