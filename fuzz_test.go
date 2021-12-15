// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package wag

import (
	"bytes"
	"errors"
	"io/ioutil"
	"path/filepath"
	"testing"

	"gate.computer/wag/buffer"
	werrors "gate.computer/wag/errors"
)

func FuzzCompile(f *testing.F) {
	filenames, err := filepath.Glob("testsuite/testdata/specdata/*.wasm")
	if err != nil {
		f.Fatal(err)
	}
	for _, filename := range filenames {
		wasm, err := ioutil.ReadFile(filename)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wasm, "", uint8(255), uint8(255))
	}

	f.Fuzz(func(t *testing.T, wasm []byte, entry string, text, data uint8) {
		config := &Config{
			Text:            buffer.NewLimited(nil, (int(text)+1)*4096),
			GlobalsMemory:   buffer.NewLimited(nil, (int(data)+1)*4096),
			MemoryAlignment: 4096,
			Entry:           entry,
		}

		if data == 0 { // Only one page.
			config.MemoryAlignment = 0
		}

		_, err := Compile(config, bytes.NewReader(wasm), testlib)
		if err == nil {
			return
		}

		var modErr werrors.ModuleError
		if errors.As(err, &modErr) {
			return
		}

		var resErr werrors.ResourceLimit
		if errors.As(err, &resErr) {
			return
		}

		t.Error(err)
	})
}
