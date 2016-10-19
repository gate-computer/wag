package gen

import (
	"io"

	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/wasm"
)

const (
	ROTableAddr = 0

	WordSize     = 8              // stack entry size
	StackReserve = WordSize + 128 // trap/import call return address + red zone
)

type OpCoder interface {
	io.Writer

	WriteByte(byte) error
	Bytes() []byte
	Len() int32

	Align(alignment int, padding byte)
}

type Coder interface {
	OpCoder

	MinMemorySize() wasm.MemorySize
	RODataAddr() int32
	TrapEntryAddr(id traps.Id) int32
	TrapTrampolineAddr(id traps.Id) int32
	OpTrapCall(id traps.Id)

	Discard(values.Operand)
	Consumed(values.Operand)
	RegAllocated(types.T, regs.R) bool
	FreeReg(types.T, regs.R)
}

type RegCoder interface {
	Coder

	TryAllocReg(t types.T) (reg regs.R, ok bool)
	AllocSpecificReg(t types.T, reg regs.R)
}
