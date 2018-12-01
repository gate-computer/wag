// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuzz

import (
	"bytes"

	"github.com/tsavola/wag"
	"github.com/tsavola/wag/internal/test/fuzz/fuzzutil"
)

func Fuzz(data []byte) int {
	config := &wag.Config{
		Text:          fuzzutil.NewTextBuffer(),
		GlobalsMemory: fuzzutil.NewGlobalsMemoryBuffer(),
	}

	_, err := wag.Compile(config, bytes.NewReader(data), fuzzutil.Resolver)
	if err != nil {
		if fuzzutil.IsFine(err) {
			return 1
		}
		return 0
	}

	return 1
}
