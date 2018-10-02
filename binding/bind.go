// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package binding

import (
	"github.com/tsavola/wag/compile"
	"github.com/tsavola/wag/wa"
)

// ImportResolver maps symbols to function vector indexes and constant values.
//
// ResolveFunc returns negative indexes; the vector is addressed from the end.
// Index -1 refers always to the trap handler, so the largest valid value that
// ResolveFunc can return is -2.
type ImportResolver interface {
	ResolveFunc(module, field string, sig wa.FuncType) (vecIndex int, err error)
	ResolveGlobal(module, field string, t wa.Type) (init uint64, err error)
}

func BindImports(mod *compile.Module, reso ImportResolver) (err error) {
	for i := 0; i < mod.NumImportFuncs(); i++ {
		index, err := reso.ResolveFunc(mod.ImportFunc(i))
		if err != nil {
			return err
		}

		mod.SetImportFunc(i, index)
	}

	for i := 0; i < mod.NumImportGlobals(); i++ {
		init, err := reso.ResolveGlobal(mod.ImportGlobal(i))
		if err != nil {
			return err
		}

		mod.SetImportGlobal(i, init)
	}

	return nil
}
