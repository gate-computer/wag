package diswag

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bnagy/gapstone"
)

func PrintTo(w io.Writer, text []byte) (err error) {
	engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
	if err != nil {
		return
	}
	defer engine.Close()

	insns, err := engine.Disasm(text, 0, 0)
	if err != nil {
		return
	}

	padding := false

	for _, insn := range insns {
		if insn.Address == 16 {
			fmt.Fprintf(w, "\n\t  ; init\n")
		}

		switch insn.Id {
		case gapstone.X86_INS_INT3, gapstone.X86_INS_ENTER:
			if !padding {
				fmt.Fprintf(w, "%08x:\n", insn.Address)
			}
			padding = true

			if insn.Id == gapstone.X86_INS_ENTER {
				padding = false
				fmt.Fprintf(w, "\n\t  ; function %d\n", binary.LittleEndian.Uint16(insn.Bytes[1:]))
			}

		default:
			padding = false
			fmt.Fprintf(w, "%08x:\t%s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		}
	}

	return
}
