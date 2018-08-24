// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/gen/regalloc"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
)

const (
	MaxImportParams = obj.StackReserve/obj.Word - 2
)

func genImportEntry(m *module.M, imp module.ImportFunc) (addr int32) {
	if debug {
		debugf("import function")
		debugDepth++
	}

	isa.AlignFunc(m)
	addr = m.Text.Addr
	m.Map.PutImportFuncAddr(addr)

	sigIndex := m.FuncSigs[imp.FuncIndex]
	sig := m.Sigs[sigIndex]

	if imp.Variadic {
		var paramRegs regalloc.Iterator
		numStackParams := paramRegs.Init(isa.ParamRegs(), sig.Args)
		if numStackParams > 0 {
			panic("import function has stack parameters")
		}

		for i := range sig.Args {
			t := sig.Args[i]
			reg := paramRegs.IterForward(t.Category())
			isa.OpStoreStackReg(m, t, -(int32(i)+1)*obj.Word, reg)
		}
	}

	isa.OpEnterImportFunc(m, imp.AbsAddr, imp.Variadic, len(sig.Args), int(sigIndex))

	if debug {
		debugDepth--
		debugf("imported function")
	}

	return
}
