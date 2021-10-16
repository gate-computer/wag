// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64
// +build arm64 wagarm64
// +build !wagamd64

package codegen

import (
	"gate.computer/wag/internal/isa/arm"
)

var (
	asm    arm.MacroAssembler
	linker arm.Linker
)
