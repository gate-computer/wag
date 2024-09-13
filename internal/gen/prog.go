// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"gate.computer/wag/internal/code"
	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/isa/program"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/trap"
)

const (
	VectorOffsetMemoryAddr    = -4 * obj.Word
	VectorOffsetCurrentMemory = -3 * obj.Word
	VectorOffsetGrowMemory    = -2 * obj.Word
	VectorOffsetTrapHandler   = -1 * obj.Word
)

type Prog struct {
	Module                  *module.M
	Text                    code.Buf
	Map                     obj.ObjectMapper
	FuncLinks               []link.FuncL
	TrapLinks               [trap.NumTraps]link.L
	TrapLinkRewindSuspended [program.NumTrapLinkRewindSuspended]link.L
	TrapLinkTruncOverflow   [program.NumTrapLinkTruncOverflow]link.L
	MemoryCopyAddr          int32
	MemoryFillAddr          int32
	LastCallAddr            int32 // Needed only by arm64 backend.

	ImportContext *module.Library // Set during import function generation.

	DebugMap obj.DebugObjectMapper
	Debugger Debugger
}
