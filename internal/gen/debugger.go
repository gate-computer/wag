// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"gate.computer/wag/internal/loader"
)

// Breakpoint information, for debugger support.
type Breakpoint struct {
	Set bool // Set by the compiler if it implemented the breakpoint.
}

type Debugger struct {
	// Breakpoints are WebAssembly code offsets.  They can be obtained from
	// DWARF debug info.
	Breakpoints map[uint32]Breakpoint

	CodeOffset int64
}

func (d *Debugger) SourceAddr(load *loader.L) uint32 {
	return uint32(load.Tell() - d.CodeOffset)
}
