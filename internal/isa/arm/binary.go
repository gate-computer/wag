// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/internal/isa/prop"
)

func (MacroAssembler) Binary(f *gen.Func, props uint16, a, b operand.O) operand.O {
	bReg, _ := getScratchReg(f, b)
	aReg, _ := allocResultReg(f, a)

	switch uint8(props) {
	case prop.BinaryIntCmp:
		f.Text.PutUint32(in.SUBSe.RdRnI3ExtRm(RegDiscard, aReg, 0, in.UXTX, bReg, a.Type))
		f.Regs.Free(a.Type, aReg)
		f.Regs.Free(b.Type, bReg)
		return operand.Flags(condition.C(props >> 8))

	case prop.BinaryIntAddsub:
		op := in.Addsub(props >> 8)
		f.Text.PutUint32(op.OpcodeRegExt().RdRnI3ExtRm(aReg, aReg, 0, in.SizeZeroExt(a.Type), bReg, a.Type))
		f.Regs.Free(b.Type, bReg)
		return operand.Reg(a.Type, aReg)

	case prop.BinaryIntLogic:
		op := in.Logic(props >> 8)
		f.Text.PutUint32(op.OpcodeReg().RdRnI6RmS2(aReg, aReg, 0, bReg, 0, a.Type))
		f.Regs.Free(b.Type, bReg)
		return operand.Reg(a.Type, aReg) // TODO: or is it?

	default:
		return TODO(props, a, b).(operand.O)
	}
}
