// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/trap"
)

func makeDebugger(breakpoints map[uint32]gen.Breakpoint, load *loader.L) gen.Debugger {
	if len(breakpoints) == 0 {
		return gen.Debugger{}
	}

	return gen.Debugger{
		Breakpoints: breakpoints,
		CodeOffset:  load.Tell(),
	}
}

func genBreakpoint(f *gen.Func, load *loader.L) {
	addr := f.Debugger.SourceAddr(load)
	bp, found := f.Debugger.Breakpoints[addr]
	if !found {
		return
	}

	opSaveOperands(f)
	asm.Trap(f, trap.Breakpoint)

	bp.Set = true
	f.Debugger.Breakpoints[addr] = bp
}
