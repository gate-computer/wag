package regs

import (
	"fmt"
)

type R int8

func (reg R) String() string {
	return fmt.Sprintf("r%d", reg)
}
