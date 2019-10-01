// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"github.com/tsavola/wag/compile"
	"github.com/tsavola/wag/internal/reader"
	"github.com/tsavola/wag/internal/test/library"
	"github.com/tsavola/wag/internal/test/runner"
)

var lib = *library.Load("testdata", runner.Resolver, func(r reader.R) library.Library {
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
