// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"bytes"
	"io"
	"os"
	"path"
	"testing"

	"gate.computer/wag/buffer"
	"gate.computer/wag/compile/event"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/test/library"
	"gate.computer/wag/section"
)

var lib = *library.Load("../testsuite/testdata/library.wasm", true, func(load *loader.L) library.L {
	mod := loadInitialSections(nil, load)
	lib := mod.asLibrary()
	return &lib
}).(*Library)

var benchDir = "../wag-bench" // Relative to project root directory.

func init() {
	if s := os.Getenv("WAG_BENCH_DIR"); s != "" {
		benchDir = path.Join("..", s)
	}
}

var (
	benchTextBuf = make([]byte, 16*1024*1024)
	benchDataBuf = make([]byte, 32*1024*1024)
)

func BenchmarkLoad000(b *testing.B)  { bench(b, "000", "run") }
func BenchmarkLoad000E(b *testing.B) { benchE(b, "000", "run", func(event.Event) {}) }
func BenchmarkLoad001(b *testing.B)  { bench(b, "001", "main") }   // Gain hello example, debug build
func BenchmarkLoad002(b *testing.B)  { bench(b, "002", "main") }   // Gain hello example, release build
func BenchmarkLoad003(b *testing.B)  { bench(b, "003", "_start") } // DOOM

func bench(b *testing.B, filename, entrySymbol string) {
	benchE(b, filename, entrySymbol, nil)
}

func benchE(b *testing.B, filename, entrySymbol string, eventHandler func(event.Event)) {
	b.Helper()

	wasm, err := os.ReadFile(path.Join("..", benchDir, filename) + ".wasm")
	if err != nil {
		if os.IsNotExist(err) {
			b.Skip(err)
		} else {
			b.Fatal(err)
		}
	}

	load := loader.New(bytes.NewReader(wasm), 0)
	loadInitialSections(nil, load)

	initLen := load.Tell()

	if err := section.SkipCustomSections(load, nil); err != nil {
		b.Fatal(err)
	}

	codePos := load.Tell()

	codePayloadLen, err := section.CopyStandardSection(io.Discard, load, section.Code, nil)
	if err != nil {
		b.Fatal(err)
	}

	if err := section.SkipCustomSections(load, nil); err != nil {
		b.Fatal(err)
	}

	dataPos := load.Tell()

	var mod Module

	b.Run("Init", func(b *testing.B) {
		b.SetBytes(initLen)

		for i := 0; i < b.N; i++ {
			mod = loadInitialSections(nil, loader.New(bytes.NewReader(wasm), 0))

			for i := 0; i < mod.NumImportFuncs(); i++ {
				// Arbitrary (but existing) implementation.
				mod.SetImportFunc(i, uint32(lib.NumImportFuncs()))
			}
		}
	})

	b.Run("Code", func(b *testing.B) {
		b.SetBytes(codePayloadLen)

		for i := 0; i < b.N; i++ {
			code := CodeConfig{
				Text:         buffer.NewStatic(benchTextBuf[:0:len(benchTextBuf)]),
				EventHandler: eventHandler,
			}

			code.LastInitFunc, _, _ = mod.ExportFunc(entrySymbol)
			loadCodeSection(&code, loader.New(bytes.NewReader(wasm[codePos:]), 0), mod, &lib.l)
		}
	})

	b.Run("Data", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			data := DataConfig{
				GlobalsMemory: buffer.NewStatic(benchDataBuf[:0:len(benchDataBuf)]),
			}

			loadDataSection(&data, loader.New(bytes.NewReader(wasm[dataPos:]), 0), mod)
		}
	})
}
