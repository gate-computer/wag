// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"bytes"
	"hash/crc32"
	"io/ioutil"
	"testing"
	"time"

	"github.com/tsavola/wag/buffer"
	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/wa"
)

type testDuration struct {
	time.Duration
}

func (target *testDuration) set(d time.Duration) {
	if target.Duration <= 0 || d < target.Duration {
		target.Duration = d
	}
}

type dummyReso struct{}

func (*dummyReso) ResolveVariadicFunc(module, field string, sig wa.FuncType) (variadic bool, index int, err error) {
	return
}

func (*dummyReso) ResolveGlobal(module, field string, t wa.Type) (init uint64, err error) {
	return
}

var loadBenchmarkReso = new(dummyReso)

const (
	loadBenchmarkFilename    = "../testdata/large.wasm"
	loadBenchmarkEntrySymbol = "run"
	loadBenchmarkMaxTextSize = 16 * 1024 * 1024
	loadBenchmarkMaxDataSize = 16 * 1024 * 1024
	loadBenchmarkTextCRC32   = 0x72a80c5c
	loadBenchmarkIgnoreCRC32 = false
)

func BenchmarkLoad(b *testing.B)       { benchmarkLoad(b, nil) }
func BenchmarkLoadEvents(b *testing.B) { benchmarkLoad(b, func(event.Event) {}) }

func benchmarkLoad(b *testing.B, eventHandler func(event.Event)) {
	b.Helper()

	wasm, err := ioutil.ReadFile(loadBenchmarkFilename)
	if err != nil {
		b.Fatal(err)
	}

	var (
		text          = make([]byte, loadBenchmarkMaxTextSize)
		globalsMemory = make([]byte, loadBenchmarkMaxDataSize)

		elapInit testDuration
		elapBind testDuration
		elapCode testDuration
		elapData testDuration
	)

	b.StopTimer()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var code = &CodeConfig{
			Text:         buffer.NewStatic(text),
			EventHandler: eventHandler,
		}

		var data = &DataConfig{
			GlobalsMemory: buffer.NewStatic(globalsMemory),
		}

		r := bytes.NewReader(wasm)

		b.StartTimer()

		t0 := time.Now()
		mod := loadInitialSections(&ModuleConfig{}, r)
		t1 := time.Now()
		bindVariadicImports(mod, loadBenchmarkReso)
		t2 := time.Now()
		code.LastInitFunc, _, _ = mod.ExportFunc(loadBenchmarkEntrySymbol)
		loadCodeSection(code, r, mod)
		t3 := time.Now()
		loadDataSection(data, r, mod)
		t4 := time.Now()

		b.StopTimer()

		elapInit.set(t1.Sub(t0))
		elapBind.set(t2.Sub(t1))
		elapCode.set(t3.Sub(t2))
		elapData.set(t4.Sub(t3))

		checkLoadBenchmarkOutput(b, code)
	}

	b.Logf("init: %v", elapInit)
	b.Logf("bind: %v", elapBind)
	b.Logf("code: %v", elapCode)
	b.Logf("data: %v", elapData)
}

func checkLoadBenchmarkOutput(b *testing.B, code *CodeConfig) {
	b.Helper()

	sum := crc32.ChecksumIEEE(code.Text.Bytes())
	if sum != loadBenchmarkTextCRC32 && !loadBenchmarkIgnoreCRC32 {
		b.Errorf("text checksum changed: 0x%08x", sum)
	}
}
