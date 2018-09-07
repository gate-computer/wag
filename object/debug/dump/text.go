// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dump

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bnagy/gapstone"

	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/trap"
)

func Text(w io.Writer, text []byte, textAddr uintptr, roDataAddr int32, funcMap []int32, ns *section.NameSection) (err error) {
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
		16: "init",
	}

	firstFuncAddr := uint(funcMap[0])

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

	sequence := 0

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

		insn.OpStr = strings.Replace(insn.OpStr, "%bl", "suspendbit", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%bh", "suspendbit", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%ebx", "suspendbit", -1)
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

		insn.OpStr = strings.Replace(insn.OpStr, "%r9b", "r9b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r9w", "r9w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r9d", "r9", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r10b", "r10b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r10w", "r10w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r10d", "r10", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r11b", "r11b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r11w", "r11w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r11d", "r11", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r12b", "r12b", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r12w", "r12w", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r12d", "r12", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%r13", "memorylimit", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r14", "memory", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%r15", "text", -1)

		insn.OpStr = strings.Replace(insn.OpStr, "%mm0", "traphandler", -1)
		insn.OpStr = strings.Replace(insn.OpStr, "%mm1", "memorygrowlimit", -1)

		switch {
		case insn.Mnemonic == "jmpq":
			continue

		case strings.HasPrefix(insn.Mnemonic, "j"):

		case insn.Mnemonic == "callq" && strings.HasPrefix(insn.OpStr, "0x"):

		case insn.Address < firstFuncAddr && (insn.Mnemonic == "movl" || insn.Mnemonic == "shlq") && strings.HasPrefix(insn.OpStr, "$") && strings.HasSuffix(insn.OpStr, ", result"):
			var n uint
			fmt.Sscanf(insn.OpStr, "$%d, %%eax", &n)
			if id := trap.Id(n); id < trap.NumTraps {
				targets[insn.Address] = "trap." + strings.Replace(id.String(), " ", "_", -1)
			}
			continue

		case strings.HasPrefix(insn.OpStr, "0x") && strings.Contains(insn.OpStr, "(, r"):
			var addr uintptr
			fmt.Sscanf(insn.OpStr, "0x%x(, ", &addr)
			relAddr := addr - uintptr(roDataAddr)
			insn.OpStr = fmt.Sprintf("rodata+0x%x(%s", relAddr, strings.SplitN(insn.OpStr, " ", 2)[1])
			continue

		default:
			continue
		}

		addr, err := strconv.ParseUint(insn.OpStr, 0, 64)
		if err != nil {
			panic(err)
		}

		name, found := targets[uint(addr)]
		if !found {
			name = fmt.Sprintf(".%x", sequence%0x10000)
			sequence++

			if uint(addr) < insn.Address {
				name += "\t\t\t; loop"
			}

			targets[uint(addr)] = name
		}

		insn.OpStr = name
	}

	lastAddr := textAddr + uintptr(insns[len(insns)-1].Address)
	addrWidth := (len(fmt.Sprintf("%x", lastAddr)) + 7) &^ 7

	var addrFmt string
	if textAddr == 0 { // relative
		addrFmt = fmt.Sprintf("%%%dx", addrWidth)
	} else {
		addrFmt = fmt.Sprintf("%%0%dx", addrWidth)
	}

	skipInt3 := false

	for _, insn := range insns {
		switch insn.Id {
		case gapstone.X86_INS_INT3:
			if skipInt3 {
				continue
			}
			skipInt3 = true

		default:
			skipInt3 = false
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

	fmt.Fprintln(w)
	return
}
