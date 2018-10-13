// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/trap"
)

const (
	VectorOffsetTrapHandler     = -2 * obj.Word
	VectorOffsetGrowMemoryLimit = -1 * obj.Word
)

type Prog struct {
	Module    *module.M
	Text      code.Buf
	Map       obj.ObjectMapper
	FuncLinks []link.FuncL
	TrapLinks [trap.NumTraps]link.L
}
