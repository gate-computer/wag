// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Convert(f *gen.Func, props uint16, resultType wa.Type, source operand.O) (result operand.O) {
	return TODO(props, resultType, source).(operand.O)
}
