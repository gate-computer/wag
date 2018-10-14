// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wagamd64 amd64,!wagarm64

package codegen

import (
	interfaces "github.com/tsavola/wag/internal/isa"
	"github.com/tsavola/wag/internal/isa/x86"
)

var (
	isa x86.ISA
	asm x86.MacroAssembler
)

func init() {
	// Consistency check
	var _ interfaces.ISA = isa
	var _ interfaces.MacroAssembler = asm
}
