package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/regs"
)

const (
	verboseRegAlloc = verbose
)

type regAllocator struct {
	groups []regGroupAllocator
}

func (ra *regAllocator) init(availableGroups [][]bool) {
	ra.groups = make([]regGroupAllocator, len(availableGroups))

	offset := 0

	for i, avail := range availableGroups {
		ra.groups[i].init(offset, avail)
		offset += len(avail)
	}
}

func (ra *regAllocator) alloc() (reg regs.R, ok bool) {
	for i := range ra.groups {
		reg, ok = ra.groups[i].allocate()
		if ok {
			return
		}
	}

	return
}

func (ra *regAllocator) allocWithPreference(prefGroup int) (reg regs.R, ok bool) {
	if prefGroup >= 0 {
		reg, ok = ra.groups[prefGroup].allocate()
		if ok {
			return
		}
	}

	for i := range ra.groups {
		if i != prefGroup {
			reg, ok = ra.groups[i].allocate()
			if ok {
				return
			}
		}
	}

	return
}

func (ra *regAllocator) free(reg regs.R) {
	for i := range ra.groups {
		if ra.groups[i].free(reg) {
			return
		}
	}
}

func (ra *regAllocator) allocated(reg regs.R) (ok bool) {
	for _, g := range ra.groups {
		ok = g.allocated(reg)
		if ok {
			return
		}
	}

	return
}

func (ra *regAllocator) postCheck(category string) {
	for _, g := range ra.groups {
		g.postCheck(category)
	}
}

type regGroupAllocator struct {
	offset int
	avail  []bool
	alloc  []bool
	phase  int
}

func (g *regGroupAllocator) init(offset int, avail []bool) {
	g.offset = offset
	g.avail = avail
	g.alloc = make([]bool, len(avail))
}

func (g *regGroupAllocator) allocate() (reg regs.R, ok bool) {
	for i := 0; i < len(g.avail); i++ {
		n := (i + g.phase) % len(g.avail)

		if g.avail[n] && !g.alloc[n] {
			g.alloc[n] = true
			reg = regs.R(g.offset + n)
			ok = true

			if verboseRegAlloc {
				for i := 0; i < debugExprDepth; i++ {
					fmt.Print("    ")
				}
				fmt.Printf("<!-- reg alloc %s -->\n", reg)
			}

			break
		}
	}

	return
}

func (g *regGroupAllocator) free(reg regs.R) (ok bool) {
	i := int(reg) - g.offset

	if i >= 0 && i < len(g.avail) && g.avail[i] {
		if !g.alloc[i] {
			panic(reg)
		}

		g.alloc[i] = false
		ok = true

		g.phase += 3

		if verboseRegAlloc {
			for i := 0; i < debugExprDepth; i++ {
				fmt.Print("    ")
			}
			fmt.Printf("<!-- reg free %s -->\n", reg)
		}
	}

	return
}

func (g *regGroupAllocator) allocated(reg regs.R) (ok bool) {
	i := int(reg) - g.offset

	if i >= 0 && i < len(g.avail) {
		ok = g.alloc[i]
	}

	return
}

func (g *regGroupAllocator) postCheck(category string) {
	for _, alloc := range g.alloc {
		if alloc {
			panic(fmt.Errorf("some %s registers not freed after function", category))
		}
	}
}
