// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

// Breakpoint information, for debugger support.
type Breakpoint struct {
	Set bool // Set by the compiler if it implemented the breakpoint.
}

type Debugger struct {
	// Breakpoints are WebAssembly code offsets.  They can be obtained from
	// DWARF debug info.
	Breakpoints map[uint32]Breakpoint

	Source     Teller
	CodeOffset int64
}

type Teller interface {
	Tell() int64
}
