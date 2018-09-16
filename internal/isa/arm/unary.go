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
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Unary(f *gen.Func, props uint16, x operand.O) operand.O {
	switch props {
	case prop.IntEqz:
		r, _ := getScratchReg(f, x)
		f.Text.PutUint32(in.ANDSs.RdRnI6RmS2(RegDiscard, r, 0, r, 0, wa.I32))
		f.Regs.Free(x.Type, r)
		return operand.Flags(condition.Eq)

	default:
		return TODO(props, x).(operand.O)
	}
}
