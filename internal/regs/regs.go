package regs

import (
	"fmt"
)

type R byte

const (
	R0      = R(0)
	R1      = R(1)
	Scratch = R(2) // for backend's use
)

func (reg R) String() string {
	switch reg {
	case R0:
		return "r0"

	case R1:
		return "r1"

	case Scratch:
		return "r2"

	default:
		return fmt.Sprintf("r%d", reg)
	}
}
