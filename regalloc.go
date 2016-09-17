package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/regs"
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
		reg, ok = ra.groups[i].alloc()
		if ok {
			return
		}
	}

	return
}

func (ra *regAllocator) allocWithPreference(prefGroup int) (reg regs.R, ok bool) {
	if prefGroup >= 0 {
		reg, ok = ra.groups[prefGroup].alloc()
		if ok {
			return
		}
	}

	for i := range ra.groups {
		if i != prefGroup {
			reg, ok = ra.groups[i].alloc()
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

func (ra *regAllocator) postCheck(category string) {
	for _, g := range ra.groups {
		g.postCheck(category)
	}
}

type regGroupAllocator struct {
	offset    int
	available []bool
	allocated []bool
	phase     int
}

func (g *regGroupAllocator) init(offset int, available []bool) {
	g.offset = offset
	g.available = available
	g.allocated = make([]bool, len(available))
}

func (g *regGroupAllocator) alloc() (reg regs.R, ok bool) {
	for i := 0; i < len(g.available); i++ {
		n := (i + g.phase) % len(g.available)

		if g.available[n] && !g.allocated[n] {
			g.allocated[n] = true
			reg = regs.R(g.offset + n)
			ok = true

			if verbose {
				for i := 0; i < debugExprDepth; i++ {
					fmt.Print("    ")
				}
				fmt.Printf("<alloc reg=\"%s\"/>\n", reg)
			}

			break
		}
	}

	return
}

func (g *regGroupAllocator) free(reg regs.R) (ok bool) {
	i := int(reg) - g.offset

	if i >= 0 && i < len(g.available) && g.available[i] {
		if !g.allocated[i] {
			panic(reg)
		}

		g.allocated[i] = false
		ok = true

		g.phase += 3

		if verbose {
			for i := 0; i < debugExprDepth; i++ {
				fmt.Print("    ")
			}
			fmt.Printf("<free reg=\"%s\"/>\n", reg)
		}
	}

	return
}

func (g *regGroupAllocator) postCheck(category string) {
	for _, alloc := range g.allocated {
		if alloc {
			panic(fmt.Errorf("some %s registers not freed after function", category))
		}
	}
}
