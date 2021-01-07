// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build gofuzz

package wag

import (
	"bytes"

	"gate.computer/wag/binary"
	"gate.computer/wag/binding"
	"gate.computer/wag/compile"
	"gate.computer/wag/internal/test/fuzzutil"
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

var fuzzResolver binding.ImportResolver = fuzzutil.Resolver{Lib: lib}

func Fuzz(data []byte) int {
	config := &Config{
		ImportResolver: fuzzResolver,
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
