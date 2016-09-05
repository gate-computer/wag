package wag

import (
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type machineCoder interface {
	UnaryOp(name string, t types.T, subject regs.R)
	BinaryOp(name string, t types.T, source, target regs.R)

	OpAddToStackPtr(int)
	OpBranchIndirect(disp regs.R) (branchAddr int)
	OpCallIndirectTrash(addr regs.R)
	OpInvalid()
	OpLoadRODataRegScaleExt(t types.T, addr int, dispType types.T, reg regs.R, scale uint8)
	OpLoadStackExt(t types.T, sourceOffset int, target regs.R)
	OpMoveExt(t types.T, source, target regs.R)
	OpMoveImm(t types.T, source interface{}, target regs.R)
	OpNop()
	OpPop(types.T, regs.R)
	OpPush(types.T, regs.R)
	OpReturn()
	OpShiftRightLogicalImm(types.T, uint8, regs.R)

	StubOpBranch()
	StubOpBranchIf(types.T, regs.R)
	StubOpBranchIfNot(types.T, regs.R)
	StubOpBranchIfNotEqualImmTrash(t types.T, value int, subject regs.R)
	StubOpBranchIfOutOfBounds(t types.T, indexReg regs.R, upperBound interface{})
	StubOpCall()

	UpdateBranches(*links.L)
	UpdateCalls(*links.L)

	Align()

	Bytes() []byte
	Len() int
}
