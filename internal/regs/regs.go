package regs

import (
	"fmt"
)

type R byte

func (reg R) String() string {
	return fmt.Sprintf("r%d", reg)
}
