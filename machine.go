package wag

import (
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type machineCoder interface {
	UnaryOp(name string, t types.T, reg regs.R)
	BinaryOp(name string, t types.T, source, target regs.R)

	OpAddToStackPtr(int)
	OpBranchIndirect(disp regs.R) (branchAddr int)
	OpInvalid()
	OpLoadRODataDispRegScaleInplace(t types.T, addr int, dispType types.T, reg regs.R, scale uint8)
	OpLoadStack(t types.T, sourceOffset int, target regs.R)
	OpMove(t types.T, source, target regs.R)
	OpMoveImm(t types.T, source interface{}, target regs.R)
	OpNop()
	OpPop(types.T, regs.R)
	OpPush(types.T, regs.R)
	OpReturn()

	StubOpBranch()
	StubOpBranchIf(types.T, regs.R)
	StubOpBranchIfNot(types.T, regs.R)
	StubOpBranchIfOutOfBounds(t types.T, indexReg regs.R, upperBound interface{})
	StubOpCall()

	UpdateBranches(*links.L)
	UpdateCalls(*links.L)

	Align()

	Bytes() []byte
	Len() int
}
