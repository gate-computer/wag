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

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/static"
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

func (*dummyReso) ResolveFunc(module, field string, sig abi.Sig) (addr uint64, err error) {
	return
}

func (*dummyReso) ResolveGlobal(module, field string, t abi.Type) (init uint64, err error) {
	return
}

var loadBenchmarkReso ImportResolver = new(dummyReso)

const (
	loadBenchmarkFilename      = "../testdata/large.wasm"
	loadBenchmarkEntrySymbol   = "run"
	loadBenchmarkEntryNumArgs  = 2
	loadBenchmarkMaxTextSize   = 16 * 1024 * 1024
	loadBenchmarkMaxDataSize   = 16 * 1024 * 1024
	loadBenchmarkMaxRODataSize = 16 * 1024 * 1024
	loadBenchmarkRODataAddr    = 0x10000
	loadBenchmarkTextCRC32     = 0xb1e93623
	loadBenchmarkRODataCRC32   = 0x7b5e3821
	loadBenchmarkIgnoreCRC32   = false
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
		roData        = make([]byte, loadBenchmarkMaxRODataSize)
		globalsMemory = make([]byte, loadBenchmarkMaxDataSize)

		elapInit testDuration
		elapReso testDuration
		elapCode testDuration
		elapData testDuration
	)

	b.StopTimer()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var mod = &Module{
			EntrySymbol: loadBenchmarkEntrySymbol,
			EntryArgs:   make([]uint64, loadBenchmarkEntryNumArgs),
		}

		var code = &CodeConfig{
			Text:         static.Buf(text),
			ROData:       static.Buf(roData),
			RODataAddr:   loadBenchmarkRODataAddr,
			EventHandler: eventHandler,
		}

		var data = &DataConfig{
			GlobalsMemory: static.Buf(globalsMemory),
		}

		r := bytes.NewReader(wasm)

		b.StartTimer()

		t0 := time.Now()
		mod.loadInitialSections(r)
		t1 := time.Now()
		mod.defineImports(loadBenchmarkReso)
		t2 := time.Now()
		loadCodeSection(code, r, mod)
		t3 := time.Now()
		loadDataSection(data, r, mod)
		t4 := time.Now()

		b.StopTimer()

		elapInit.set(t1.Sub(t0))
		elapReso.set(t2.Sub(t1))
		elapCode.set(t3.Sub(t2))
		elapData.set(t4.Sub(t3))

		checkLoadBenchmarkOutput(b, code)
	}

	b.Logf("init: %v", elapInit)
	b.Logf("reso: %v", elapReso)
	b.Logf("code: %v", elapCode)
	b.Logf("data: %v", elapData)
}

func checkLoadBenchmarkOutput(b *testing.B, code *CodeConfig) {
	b.Helper()

	sum := crc32.ChecksumIEEE(code.Text.Bytes())
	if sum != loadBenchmarkTextCRC32 && !loadBenchmarkIgnoreCRC32 {
		b.Errorf("text checksum changed: 0x%08x", sum)
	}

	sum = crc32.ChecksumIEEE(code.ROData.Bytes())
	if sum != loadBenchmarkRODataCRC32 && !loadBenchmarkIgnoreCRC32 {
		b.Errorf("rodata checksum changed: 0x%08x", sum)
	}
}
