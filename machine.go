package wag

import (
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type machineCoder interface {
	TypedBinaryInst(t types.T, name string, source, target regs.R)

	InstAddToStackPtr(int)
	InstBranchStub()
	InstBranchIfNotStub(regs.R)
	InstCallStub()
	InstClear(regs.R)
	InstInvalid()
	InstMoveImmToReg(t types.T, source interface{}, target regs.R)
	InstMoveRegToReg(source, target regs.R)
	InstMoveVarToReg(sourceOffset int, target regs.R)
	InstPop(regs.R)
	InstPush(regs.R)
	InstRet()

	UpdateBranches(*links.L)
	UpdateCalls(*links.L)

	Bytes() []byte
	Len() int
}
