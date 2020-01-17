// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"errors"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/reader"
	"github.com/tsavola/wag/trap"
)

func makeDebugger(config *gen.DebuggerSupport, r reader.R) (debugger gen.Debugger) {
	if config == nil {
		return
	}

	debugger.DebuggerSupport = *config
	if len(debugger.Breakpoints) == 0 {
		return
	}

	source, ok := r.(gen.Teller)
	if !ok {
		panic(errors.New("setting breakpoints without position-aware reader"))
	}

	debugger.Source = source
	debugger.CodeOffset = source.Tell()
	return
}

func genBreakpoint(f *gen.Func) {
	if f.Debugger.Source == nil {
		return
	}

	offset := uint32(f.Debugger.Source.Tell() - f.Debugger.CodeOffset)
	bp, found := f.Debugger.Breakpoints[offset]
	if !found {
		return
	}

	opSaveOperands(f)
	asm.Trap(f, trap.Breakpoint)

	bp.Set = true
	f.Debugger.Breakpoints[offset] = bp
}
