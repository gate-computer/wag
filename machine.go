package wag

import (
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type machineCoder interface {
	UnaryOp(t types.T, name string, reg regs.R)
	BinaryOp(t types.T, name string, source, target regs.R)

	OpAddToStackPtr(int)
	OpClear(regs.R)
	OpInvalid()
	OpLoadStack(t types.T, sourceOffset int, target regs.R)
	OpMove(t types.T, source, target regs.R)
	OpMoveImm(t types.T, source interface{}, target regs.R)
	OpNop()
	OpPop(types.T, regs.R)
	OpPush(types.T, regs.R)
	OpReturn()

	StubOpBranch()
	StubOpBranchIfNot(types.T, regs.R)
	StubOpCall()

	UpdateBranches(*links.L)
	UpdateCalls(*links.L)

	Align()

	Bytes() []byte
	Len() int
}
