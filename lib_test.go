// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"gate.computer/wag/binary"
	"gate.computer/wag/binding"
	"gate.computer/wag/compile"
	"gate.computer/wag/internal/test/library"
)

var testlib = *library.Load("testsuite/testdata/library.wasm", true, func(r binary.Reader) library.L {
	mod, err := compile.LoadInitialSections(nil, r)
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
