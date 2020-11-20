// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/isa/arm/in"
)

const (
	RegResult         = reg.Result
	RegScratch        = reg.ScratchISA
	RegImportVariadic = reg.R(2)  // <- AllocIntFirst
	_                 = reg.R(25) // <- AllocIntLast
	RegMemoryBase     = reg.R(26)
	RegTextBase       = reg.R(27)
	RegStackLimit4    = reg.R(28)
	RegFakeSP         = in.RegFakeSP
	RegLink           = reg.R(30)
	RegScratch2       = reg.R(30)
	RegRealSP         = reg.R(31)
	RegZero           = reg.R(31)
	RegDiscard        = reg.R(31)
)
