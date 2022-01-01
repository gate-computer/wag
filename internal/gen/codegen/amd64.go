// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64
// +build amd64 wagamd64
// +build !wagarm64

package codegen

import (
	"gate.computer/wag/internal/isa/amd64"
)

var (
	asm    amd64.MacroAssembler
	linker amd64.Linker
)
