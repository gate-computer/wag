// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wagarm64 arm64,!wagamd64

package codegen

import (
	"gate.computer/wag/internal/isa/arm"
)

var (
	asm    arm.MacroAssembler
	linker arm.Linker
)
