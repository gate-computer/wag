// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build debug indebug

package in

import (
	"fmt"

	"github.com/knightsc/gapstone"
)

const (
	debugInstructionBytes  = true
	debugImplicitRegisters = true
)

var (
	debugEngine gapstone.Engine
)

func init() {
	engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
	if err != nil {
		panic(err)
	}

	err = engine.SetOption(gapstone.CS_OPT_SYNTAX, gapstone.CS_OPT_SYNTAX_ATT)
	if err != nil {
		panic(err)
	}

	debugEngine = engine
}

func debugPrintInsn(data []byte) {
	var (
		hex string
	)

	if debugInstructionBytes {
		hex = " ;"
		for i, b := range data {
			if i > 0 && (i&3) == 0 {
				hex += " "
			}
			hex += fmt.Sprintf(" %02x", b)
		}
	}

	insns, err := debugEngine.Disasm(data, 0, 0)
	if err != nil || len(insns) == 0 {
		if debugInstructionBytes {
			print(fmt.Sprintf("indebug:%s\n", hex))
		}
		panic(err)
	}

	prefix := "indebug"

	for _, insn := range insns {
		var (
			read  string
			write string
		)

		if debugImplicitRegisters {
			if len(insn.RegistersRead) > 0 {
				read = " ; read"
				for _, r := range insn.RegistersRead {
					read += fmt.Sprintf(" r%d", r)
				}
			}

			if len(insn.RegistersWritten) > 0 {
				write = " ; write"
				for _, r := range insn.RegistersWritten {
					write += fmt.Sprintf(" r%d", r)
				}
			}
		}

		print(fmt.Sprintf("%7s: %-7s %-25s%s%s%s\n", prefix, insn.Mnemonic, insn.OpStr, hex, read, write))

		prefix = ""

		if hex != "" {
			hex = " ;"
		}
	}
}
