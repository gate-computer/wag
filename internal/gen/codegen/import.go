// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/module"
)

func genImportTrampoline(p *gen.Prog, m *module.M, funcIndex int, imp module.ImportFunc) (addr int32) {
	isa.AlignFunc(p)
	addr = p.Text.Addr
	p.Map.PutImportFuncAddr(addr)

	sigIndex := m.FuncSigs[funcIndex]
	sig := m.Sigs[sigIndex]

	asm.JumpToImportFunc(p, imp.Addr, imp.Variadic, len(sig.Args), int(sigIndex))
	return
}
