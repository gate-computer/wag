// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/module"
)

func genImportTrampoline(m *module.M, imp module.ImportFunc) (addr int32) {
	isa.AlignFunc(m)
	addr = m.Text.Addr
	m.Map.PutImportFuncAddr(addr)

	sigIndex := m.FuncSigs[imp.FuncIndex]
	sig := m.Sigs[sigIndex]

	asm.JumpToImportFunc(m, imp.AbsAddr, imp.Variadic, len(sig.Args), int(sigIndex))
	return
}