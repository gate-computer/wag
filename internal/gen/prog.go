// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/isa/program"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/trap"
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
	LastCallAddr            int32 // Needed only by arm backend.

	ImportContext *module.Library // Set during import function generation.
}
