// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/operand"
)

func (MacroAssembler) Select(f *gen.Func, a, b, condOperand operand.O) operand.O {
	return TODO(a, b, condOperand).(operand.O)
}
