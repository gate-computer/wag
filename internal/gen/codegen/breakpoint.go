// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"errors"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/reader"
)

func makeDebugger(breakpoints map[uint32]gen.Breakpoint, r reader.R) gen.Debugger {
	if len(breakpoints) == 0 {
		return gen.Debugger{}
	}

	source, ok := r.(gen.Teller)
	if !ok {
		panic(errors.New("setting breakpoints without position-aware reader"))
	}

	return gen.Debugger{
		Breakpoints: breakpoints,
		Source:      source,
		CodeOffset:  source.Tell(),
	}
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
	asm.Breakpoint(f)

	bp.Set = true
	f.Debugger.Breakpoints[offset] = bp
}
