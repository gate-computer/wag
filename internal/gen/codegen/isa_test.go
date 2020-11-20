// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"testing"

	interfaces "gate.computer/wag/internal/isa"
)

func TestISAInterfaces(*testing.T) {
	var _ interfaces.MacroAssembler = asm
	var _ interfaces.Linker = linker
}
