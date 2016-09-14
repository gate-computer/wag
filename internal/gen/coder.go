package gen

import (
	"io"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type Coder interface {
	io.Writer
	WriteByte(byte) error
	Bytes() []byte
	Len() int

	TrapLinks() *TrapLinks
}

type RegCoder interface {
	Coder

	OpAllocReg(t types.T) regs.R
	FreeReg(types.T, regs.R)
}

type TrapLinks struct {
	DivideByZero          links.L
	CallStackExhausted    links.L
	IndirectCallIndex     links.L
	IndirectCallSignature links.L
	Unreachable           links.L
}
