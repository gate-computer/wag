// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build gofuzz

package wag

import (
	"bytes"

	"github.com/tsavola/wag/compile"
	"github.com/tsavola/wag/internal/reader"
	"github.com/tsavola/wag/internal/test/fuzzutil"
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

func Fuzz(data []byte) int {
	config := &Config{
		ImportResolver: fuzzutil.Resolver,
		Text:           fuzzutil.NewTextBuffer(),
		GlobalsMemory:  fuzzutil.NewGlobalsMemoryBuffer(),
	}

	_, err := Compile(config, bytes.NewReader(data), lib)
	result, ok := fuzzutil.Result(err)
	if !ok {
		panic(err)
	}
	return result
}
