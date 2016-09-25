package gen

import (
	"io"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

type Coder interface {
	io.Writer
	WriteByte(byte) error
	Bytes() []byte
	Len() int

	MinMemorySize() int
	RODataAddr() int
	TrapLinks() *TrapLinks

	Discard(types.T, values.Operand)
	Consumed(types.T, values.Operand)
	RegAllocated(types.T, regs.R) bool
	FreeReg(types.T, regs.R)
	AddCallSite(*links.L)
	AddIndirectCallSite()
	AddStackUsage(size int)
}

type RegCoder interface {
	Coder

	TryAllocReg(t types.T) (reg regs.R, ok bool)
}

type TrapLinks struct {
	Exit links.L

	CallStackExhausted    links.L
	IndirectCallIndex     links.L
	IndirectCallSignature links.L
	MemoryOutOfBounds     links.L
	Unreachable           links.L

	IntegerDivideByZero links.L
	IntegerOverflow     links.L
}
