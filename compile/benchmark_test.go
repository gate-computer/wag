// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"gate.computer/wag/buffer"
	"gate.computer/wag/compile/event"
	"gate.computer/wag/section"
)

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

	wasm, err := ioutil.ReadFile(path.Join("..", benchDir, filename) + ".wasm")
	if err != nil {
		if os.IsNotExist(err) {
			b.Skip(err)
		} else {
			b.Fatal(err)
		}
	}

	r := bytes.NewReader(wasm)
	loadInitialSections(nil, r)

	initLen := len(wasm) - r.Len()

	if err := section.SkipCustomSections(r, nil); err != nil {
		b.Fatal(err)
	}

	codePos := len(wasm) - r.Len()

	codePayloadLen, err := section.CopyStandardSection(ioutil.Discard, r, section.Code, nil)
	if err != nil {
		b.Fatal(err)
	}

	if err := section.SkipCustomSections(r, nil); err != nil {
		b.Fatal(err)
	}

	dataPos := len(wasm) - r.Len()

	var mod Module

	b.Run("Init", func(b *testing.B) {
		b.SetBytes(int64(initLen))

		for i := 0; i < b.N; i++ {
			mod = loadInitialSections(nil, bytes.NewReader(wasm))

			for i := 0; i < mod.NumImportFuncs(); i++ {
				// Arbitrary (but existing) implementation.
				mod.SetImportFunc(i, uint32(lib.NumImportFuncs()))
			}
		}
	})

	b.Run("Code", func(b *testing.B) {
		b.SetBytes(int64(codePayloadLen))

		for i := 0; i < b.N; i++ {
			code := CodeConfig{
				Text:         buffer.NewStatic(benchTextBuf[:0:len(benchTextBuf)]),
				EventHandler: eventHandler,
			}

			code.LastInitFunc, _, _ = mod.ExportFunc(entrySymbol)
			loadCodeSection(&code, bytes.NewReader(wasm[codePos:]), mod, &lib.l)
		}
	})

	b.Run("Data", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			data := DataConfig{
				GlobalsMemory: buffer.NewStatic(benchDataBuf[:0:len(benchDataBuf)]),
			}

			loadDataSection(&data, bytes.NewReader(wasm[dataPos:]), mod)
		}
	})
}
