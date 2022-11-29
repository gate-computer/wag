// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64

package codegen

import (
	"gate.computer/wag/internal/isa/arm64"
)

var (
	asm    arm64.MacroAssembler
	linker arm64.Linker
)
