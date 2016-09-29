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
	name  string
}

func (ra *regAllocator) init(avail uint32, name string) {
	ra.avail = avail
	ra.freed = avail
	ra.name = name
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
				fmt.Printf("<!-- reg alloc %s %s -->\n", ra.name, reg)
			}

			break
		}

		reg++
	}

	return
}

func (ra *regAllocator) allocSpecific(reg regs.R) {
	if verboseRegAlloc {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<!-- reg alloc %s %s specifically -->\n", ra.name, reg)
	}

	mask := uint32(1 << reg)

	if (ra.freed & mask) == 0 {
		panic(reg)
	}

	ra.freed &^= mask
}

func (ra *regAllocator) free(reg regs.R) {
	mask := uint32(1 << reg)

	if verboseRegAlloc {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		if (ra.avail & mask) == 0 {
			fmt.Printf("<!-- reg free %s %s (nop) -->\n", ra.name, reg)
		} else {
			fmt.Printf("<!-- reg free %s %s -->\n", ra.name, reg)
		}
	}

	if (ra.freed & mask) != 0 {
		panic(reg)
	}

	if (ra.avail & mask) == 0 {
		return
	}

	ra.freed |= mask
}

func (ra *regAllocator) allocated(reg regs.R) bool {
	if verboseRegAlloc {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<!-- reg check %s %s -->\n", ra.name, reg)
	}

	mask := uint32(1 << reg)

	return ((ra.avail &^ ra.freed) & mask) != 0
}

func (ra *regAllocator) postCheck() {
	if ra.freed != ra.avail {
		panic(fmt.Errorf("some %s registers not freed after function", ra.name))
	}
}
