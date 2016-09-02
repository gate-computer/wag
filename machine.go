package wag

import (
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type machineCoder interface {
	UnaryOp(name string, t types.T, reg regs.R)
	BinaryOp(name string, t types.T, source, target regs.R)

	FunctionPrologue()
	FunctionEpilogue()

	OpAddToStackPtr(int)
	OpInvalid()
	OpLoadLocal(t types.T, sourceOffset int, target regs.R)
	OpMove(t types.T, source, target regs.R)
	OpMoveImm(t types.T, source interface{}, target regs.R)
	OpNop()
	OpPop(types.T, regs.R)
	OpPush(types.T, regs.R)

	StubOpBranch()
	StubOpBranchIf(types.T, regs.R)
	StubOpBranchIfNot(types.T, regs.R)
	StubOpCall()

	UpdateBranches(*links.L)
	UpdateCalls(*links.L)

	Align()

	Bytes() []byte
	Len() int
}
