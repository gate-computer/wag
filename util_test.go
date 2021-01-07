// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"gate.computer/wag/binary"
	"gate.computer/wag/compile"
	"gate.computer/wag/internal/test/library"
	"gate.computer/wag/internal/test/runner"
)

var lib = *library.Load("testdata", runner.Resolver, func(r binary.Reader) library.Library {
	mod, err := compile.LoadInitialSections(nil, r)
	if err != nil {
		panic(err)
	}

	lib, err := mod.AsLibrary()
	if err != nil {
		panic(err)
	}

	return &lib
}).(*compile.Library)
