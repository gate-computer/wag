// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"gate.computer/wag/binding"
	"gate.computer/wag/compile"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/test/library"
)

var testlib = *library.Load("testsuite/testdata/library.wasm", true, func(load *loader.L) library.L {
	mod, err := compile.LoadInitialSections(nil, load)
	if err != nil {
		panic(err)
	}

	lib, err := mod.AsLibrary()
	if err != nil {
		panic(err)
	}

	for i := 0; i < lib.NumImportFuncs(); i++ {
		lib.SetImportFunc(i, binding.VectorIndexLastImport-i) // Dummy values.
	}

	return &lib
}).(*compile.Library)
