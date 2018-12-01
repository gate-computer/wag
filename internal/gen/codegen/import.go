// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/module"
)

func genImportTrampoline(p *gen.Prog, m *module.M, funcIndex int, imp module.ImportFunc) (addr int32) {
	asm.AlignFunc(p)
	addr = p.Text.Addr
	p.Map.PutImportFuncAddr(uint32(addr))

	sigIndex := m.Funcs[funcIndex]
	sig := m.Types[sigIndex]

	asm.JumpToImportFunc(p, imp.VecIndex, imp.Variadic, len(sig.Params), int(sigIndex))
	return
}
