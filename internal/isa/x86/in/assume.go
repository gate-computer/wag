// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"github.com/tsavola/wag/internal/gen/reg"
)

const (
	RegResult     = reg.Result
	RegScratch    = reg.ScratchISA
	RegZero       = reg.R(2)
	RegStackLimit = reg.R(3)
	RegStack      = reg.R(4)
	RegMemoryBase = reg.R(14)
	RegTextBase   = reg.R(15)
)

type BaseReg reg.R

const (
	BaseScratch = BaseReg(RegScratch)
	BaseZero    = BaseReg(RegZero)
	BaseMemory  = BaseReg(RegMemoryBase)
	BaseText    = BaseReg(RegTextBase)
)
