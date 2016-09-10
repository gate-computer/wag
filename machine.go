package wag

import (
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/traps"
)

type machineCoder interface {
	DivideByZeroTarget() *links.L

	UnaryOp(name string, t types.T)
	BinaryOp(name string, t types.T)

	OpAbort()
	OpAddToStackPtr(int)
	OpBranchIndirect(disp regs.R) (branchAddr int)
	OpCallIndirectDisp32FromStack(ptrStackOffset int)
	OpClear(regs.R)
	OpLoadROFloatDisp(t types.T, target regs.R, addr int)
	OpLoadROIntIndex32ScaleDisp(t types.T, reg regs.R, scale uint8, addr int, signExt bool)
	OpLoadStack(t types.T, target regs.R, sourceOffset int)
	OpMove(t types.T, target, source regs.R)
	OpMoveImmediateInt(t types.T, target regs.R, token interface{})
	OpPop(types.T, regs.R)
	OpPush(types.T, regs.R)
	OpReturn()
	OpShiftRightLogical32Bits(subject regs.R)
	OpStoreStack(t types.T, targetOffset int, source regs.R)
	OpTrap(traps.Id)

	StubOpBranch()
	StubOpBranchIf(regs.R)
	StubOpBranchIfNot(regs.R)
	StubOpBranchIfNotEqualImm32(subject regs.R, value int)
	StubOpBranchIfOutOfBounds(indexReg regs.R, upperBound int)
	StubOpBranchIfStackExhausted() (stackUsageAddr int)
	StubOpCall()

	UpdateBranches(*links.L)
	UpdateCalls(*links.L)
	UpdateStackDisp(addr int, value int)

	AlignFunction()

	Bytes() []byte
	Len() int
}
