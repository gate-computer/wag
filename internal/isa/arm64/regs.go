// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64

package arm64

import (
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/isa/arm64/in"
)

const (
	RegResult      = reg.Result
	RegScratch     = reg.ScratchISA
	RegTrap        = reg.R(2) // <- AllocIntFirst, AllocFloatFirst
	RegRestartSP   = reg.R(3)
	_              = reg.R(25) // <- AllocIntLast
	RegMemoryBase  = reg.R(26)
	RegTextBase    = reg.R(27)
	RegStackLimit4 = reg.R(28)
	RegFakeSP      = in.RegFakeSP
	RegLink        = reg.R(30)
	RegScratch2    = reg.R(30)
	RegRealSP      = reg.R(31)
	RegZero        = reg.R(31)
	RegDiscard     = reg.R(31) // <- AllocFloatLast
)
