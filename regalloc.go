package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/regs"
)

const (
	verboseRegAlloc = verbose
)

type regAllocator struct {
	avail []int32
	alloc uint64 // support up to 64 registers
}

func (ra *regAllocator) init(avail []int32) {
	ra.avail = avail
}

func (ra *regAllocator) allocate() (reg regs.R, ok bool) {
	bestScore := int32(0)
	var bestMask uint64

	mask := uint64(1)
	for i, score := range ra.avail {
		if (ra.alloc & mask) == 0 {
			if score > bestScore {
				bestScore = score
				bestMask = mask
				reg = regs.R(i)
			}
		}
		mask <<= 1
	}

	if bestScore > 0 {
		ra.alloc |= bestMask
		ok = true

		if verboseRegAlloc {
			for i := 0; i < debugExprDepth; i++ {
				fmt.Print("    ")
			}
			fmt.Printf("<!-- reg alloc %s -->\n", reg)
		}
	}

	return
}

func (ra *regAllocator) allocateSpecific(reg regs.R) {
	mask := uint64(1 << uint(reg))

	if (ra.alloc & mask) == 0 {
		if i := int(reg); i < len(ra.avail) && ra.avail[i] > 0 {
			ra.alloc |= mask

			if verboseRegAlloc {
				for i := 0; i < debugExprDepth; i++ {
					fmt.Print("    ")
				}
				fmt.Printf("<!-- reg alloc %s specifically -->\n", reg)
			}

			return
		}
	}

	panic(reg)
}

func (ra *regAllocator) free(reg regs.R) {
	mask := uint64(1 << uint(reg))

	if (ra.alloc & mask) == 0 {
		if i := int(reg); i < len(ra.avail) && ra.avail[i] <= 0 {
			return
		}
		panic(reg)
	}

	ra.alloc &^= mask

	if verboseRegAlloc {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<!-- reg free %s -->\n", reg)
	}
}

func (ra *regAllocator) allocated(reg regs.R) bool {
	mask := uint64(1 << uint(reg))

	if verboseRegAlloc {
		for i := 0; i < debugExprDepth; i++ {
			fmt.Print("    ")
		}
		fmt.Printf("<!-- reg check %s -->\n", reg)
	}

	return (ra.alloc & mask) != 0
}

func (ra *regAllocator) postCheck(category string) {
	if ra.alloc != 0 {
		panic(fmt.Errorf("some %s registers not freed after function", category))
	}
}
