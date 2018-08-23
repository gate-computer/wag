// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package disasm

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bnagy/gapstone"

	"github.com/tsavola/wag/object"
	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/trap"
)

func Fprint(w io.Writer, text []byte, funcMap []object.TextAddr, ns *section.NameSection) (err error) {
	var names []section.FuncName
	if ns != nil {
		names = ns.FuncNames
	}

	engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
	if err != nil {
		return
	}
	defer engine.Close()

	err = engine.SetOption(gapstone.CS_OPT_SYNTAX, gapstone.CS_OPT_SYNTAX_ATT)
	if err != nil {
		return
	}

	insns, err := engine.Disasm(text, 0, 0)
	if err != nil {
		return
	}

	targets := map[uint]string{
		16: "start",
	}

	firstFuncAddr := uint(funcMap[0])

	for i := 0; len(funcMap) > 0; i++ {
		addr := funcMap[0]
		funcMap = funcMap[1:]

		var name string
		if i < len(names) {
			name = names[i].FunName
		} else {
			name = fmt.Sprintf("func_%d", i)
		}

		targets[uint(addr)] = name
	}

	sequence := 0

	for i := range insns {
		insn := insns[i]
		var name string

		switch {
		case insn.Mnemonic == "jmpq":
			continue

		case strings.HasPrefix(insn.Mnemonic, "j"):

		case insn.Mnemonic == "callq" && strings.HasPrefix(insn.OpStr, "0x"):

		case insn.Address < firstFuncAddr && insn.Mnemonic == "movl" && strings.HasPrefix(insn.OpStr, "$") && strings.HasSuffix(insn.OpStr, ", %eax"):
			var n uint
			fmt.Sscanf(insn.OpStr, "$%d, %%eax", &n)
			if id := trap.Id(n); id < trap.NumTraps {
				targets[insn.Address] = strings.Replace(id.String(), " ", "_", -1)
			}
			continue

		default:
			continue
		}

		addr, err := strconv.ParseUint(insn.OpStr, 0, 32)
		if err != nil {
			panic(err)
		}

		name, found := targets[uint(addr)]
		if !found {
			name = fmt.Sprintf(".L%d", sequence)
			sequence++

			targets[uint(addr)] = name
		}

		insns[i].OpStr = name
	}

	skip := false

	for _, insn := range insns {
		name, found := targets[insn.Address]
		if found {
			if !strings.HasPrefix(name, ".") && name != "exit" {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "%s:\n", name)
		}

		switch insn.Id {
		case gapstone.X86_INS_INT3:
			if skip {
				continue
			}
			skip = true
			fallthrough

		default:
			fmt.Fprintf(w, "\t%s\t%s\n", insn.Mnemonic, insn.OpStr)
		}
	}

	fmt.Fprintln(w)
	return
}
