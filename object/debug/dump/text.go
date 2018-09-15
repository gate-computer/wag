// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dump

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/bnagy/gapstone"

	"github.com/tsavola/wag/section"
)

func Text(w io.Writer, text []byte, textAddr, roDataAddr uintptr, funcMap []int32, ns *section.NameSection) (err error) {
	var names []section.FuncName
	if ns != nil {
		names = ns.FuncNames
	}

	engine, err := gapstone.New(csArch, csMode)
	if err != nil {
		return err
	}
	defer engine.Close()

	err = engine.SetOption(gapstone.CS_OPT_SYNTAX, csSyntax)
	if err != nil {
		return
	}

	insns, err := engine.Disasm(text, 0, 0)
	if err != nil {
		return
	}

	firstFuncAddr := uint(funcMap[0])

	targets := map[uint]string{
		16: "init",
	}

	for i := 0; len(funcMap) > 0; i++ {
		addr := funcMap[0]
		funcMap = funcMap[1:]

		var name string
		if i < len(names) {
			name = names[i].FunName
		} else {
			name = fmt.Sprintf("func.%d", i)
		}

		targets[uint(addr)] = name
	}

	rewriteText(insns, targets, firstFuncAddr, roDataAddr)

	lastAddr := textAddr + uintptr(insns[len(insns)-1].Address)
	addrWidth := (len(fmt.Sprintf("%x", lastAddr)) + 7) &^ 7

	var addrFmt string
	if textAddr == 0 { // relative
		addrFmt = fmt.Sprintf("%%%dx", addrWidth)
	} else {
		addrFmt = fmt.Sprintf("%%0%dx", addrWidth)
	}

	skipPad := false

	for _, insn := range insns {
		switch insn.Id {
		case padInsn:
			if skipPad {
				continue
			}
			skipPad = true

		default:
			skipPad = false
		}

		addr := textAddr + uintptr(insn.Address)

		name, found := targets[insn.Address]
		if found {
			if strings.HasPrefix(name, ".") {
				fmt.Fprintf(w, addrFmt+" %s:", addr, strings.TrimSpace(strings.Split(name, ";")[0]))
			} else {
				fmt.Fprintf(w, "\n%s:\n"+addrFmt, name, addr)
			}
		} else {
			fmt.Fprintf(w, addrFmt, addr)
		}

		fmt.Fprint(w, "\t", strings.TrimSpace(fmt.Sprintf("%s\t%s", insn.Mnemonic, insn.OpStr)), "\n")
	}

	if false {
		for {
			insns, err := engine.Disasm(text, uint64(textAddr), 0)
			if err != nil {
				return err
			}

			for _, insn := range insns {
				fmt.Fprintf(w, "%x", insn.Address)
				fmt.Fprintln(w, "\t"+strings.TrimSpace(fmt.Sprintf("%s\t%s", insn.Mnemonic, insn.OpStr)))
			}

			text = text[len(insns)*4:]
			textAddr += uintptr(len(insns) * 4)
			if len(text) == 0 {
				break
			}

			fmt.Fprintf(w, "%x", textAddr)
			fmt.Fprintf(w, "\t; %08x\n", binary.LittleEndian.Uint32(text))

			text = text[4:]
			textAddr += 4
			if len(text) == 0 {
				break
			}
		}
	}

	fmt.Fprintln(w)
	return nil
}
