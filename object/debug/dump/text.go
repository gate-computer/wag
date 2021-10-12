// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo

package dump

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"gate.computer/wag/object/abi"
	"gate.computer/wag/section"
	"github.com/knightsc/gapstone"
)

func Text(w io.Writer, text []byte, textAddr uintptr, funcAddrs []uint32, ns *section.NameSection) error {
	var names []section.FuncName
	if ns != nil {
		names = ns.FuncNames
	}

	engine, err := gapstone.New(csArch, csMode)
	if err != nil {
		return err
	}
	defer engine.Close()

	if err := engine.SetOption(gapstone.CS_OPT_SYNTAX, csSyntax); err != nil {
		return err
	}

	var insns []gapstone.Instruction

	for offset := uint64(0); true; {
		is, err := engine.Disasm(text[offset:], uint64(textAddr)+offset, 0)
		if err != nil {
			fmt.Fprintf(w, "Disassembly error at %x: %v\n", uint64(textAddr)+offset, err)
		}

		if len(is) > 0 {
			insns = append(insns, is...)

			latest := is[len(is)-1]
			offset = uint64(latest.Address+latest.Size) - uint64(textAddr)
		}

		skipTo := (offset + 4) &^ 3 // try next 32-bit word
		if skipTo >= uint64(len(text)) {
			break
		}
		offset = skipTo
	}

	for i := 0; i < len(insns)-1; i++ {
		end := insns[i].Address + insns[i].Size
		next := insns[i+1].Address
		if end < next {
			size := next - end
			if size > 4 {
				size = 4
			}

			repr := "?"
			if size == 4 {
				repr = fmt.Sprintf("%08x", binary.LittleEndian.Uint32(text[uintptr(end)-textAddr:]))
			}

			insn := gapstone.Instruction{
				InstructionHeader: gapstone.InstructionHeader{
					Address:  end,
					Size:     size,
					Mnemonic: repr,
				},
			}
			insns = append(insns[:i+1], append([]gapstone.Instruction{insn}, insns[i+1:]...)...)
		}
	}

	firstFuncAddr := uint(textAddr) + uint(funcAddrs[0])

	targets := map[uint]string{
		uint(textAddr) + abi.TextAddrResume: "resume",
		uint(textAddr) + abi.TextAddrEnter:  "enter",
	}

	for i := 0; len(funcAddrs) > 0; i++ {
		addr := uint(textAddr) + uint(funcAddrs[0])
		funcAddrs = funcAddrs[1:]

		var name string
		if i < len(names) {
			name = names[i].FuncName
		}
		if name == "" {
			name = fmt.Sprintf("func.%d", i)
		}

		targets[addr] = name
	}

	rewriteText(insns, targets, textAddr, firstFuncAddr)

	lastAddr := uintptr(insns[len(insns)-1].Address)
	addrWidth := (len(fmt.Sprintf("%x", lastAddr)) + 7) &^ 7

	var addrFmt string
	if textAddr == 0 { // relative
		addrFmt = fmt.Sprintf("%%%dx", addrWidth)
	} else {
		addrFmt = fmt.Sprintf("%%0%dx", addrWidth)
	}

	prevWasPad := false

	for _, insn := range insns {
		if insn.Id == padInsn {
			prevWasPad = true
			continue
		}

		addr := uintptr(insn.Address)

		name, found := targets[insn.Address]
		if found {
			if strings.HasPrefix(name, ".") {
				fmt.Fprintf(w, addrFmt+" %s:", addr, strings.TrimSpace(strings.Split(name, ";")[0]))
			} else {
				fmt.Fprintf(w, "\n%s:\n"+addrFmt, name, addr)
			}
		} else {
			if prevWasPad {
				fmt.Fprintln(w)
			}

			fmt.Fprintf(w, addrFmt, addr)
		}

		fmt.Fprint(w, "\t", strings.TrimSpace(fmt.Sprintf("%s\t%s", insn.Mnemonic, insn.OpStr)), "\n")

		prevWasPad = false
	}

	fmt.Fprintln(w)
	return nil
}
