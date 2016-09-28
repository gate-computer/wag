package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/regs"
)

const (
	verboseRegAlloc = verbose
)

type regAllocator struct {
	avail uint32
	freed uint32
}

func (ra *regAllocator) init(avail uint32) {
	ra.avail = avail
	ra.freed = avail
}

func (ra *regAllocator) alloc() (reg regs.R, ok bool) {
	for bits := ra.freed; bits != 0; bits >>= 1 {
		if (bits & 1) != 0 {
			ra.freed &^= uint32(1 << reg)
			ok = true

			if verboseRegAlloc {
				for i := 0; i < debugExprDepth; i++ {
					fmt.Print("    ")
				}
				fmt.Printf("<!-- reg alloc %s -->\n", reg)
			}

			break
		}

		reg++
	}

	return
}

func (ra *regAllocator) allocSpecific(reg regs.R) {
	mask := uint32(1 << reg)

	if (ra.freed & mask) == 0 {
		panic(reg)
	}

	ra.freed &^= mask

	if verboseRegAlloc {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<!-- reg alloc %s specifically -->\n", reg)
	}
}

func (ra *regAllocator) free(reg regs.R) {
	mask := uint32(1 << reg)

	if (ra.freed & mask) != 0 {
		panic(reg)
	}

	if (ra.avail & mask) == 0 {
		return
	}

	ra.freed |= mask

	if verboseRegAlloc {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<!-- reg free %s -->\n", reg)
	}
}

func (ra *regAllocator) allocated(reg regs.R) bool {
	if verboseRegAlloc {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<!-- reg check %s -->\n", reg)
	}

	mask := uint32(1 << reg)

	return ((ra.avail &^ ra.freed) & mask) != 0
}

func (ra *regAllocator) postCheck(category string) {
	if ra.freed != ra.avail {
		panic(fmt.Errorf("some %s registers not freed after function", category))
	}
}
