// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"bytes"
	"hash/crc32"
	"io/ioutil"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/internal/test/runner"
	"github.com/tsavola/wag/object/debug/dump"
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

type dummyEnv struct{}

func (*dummyEnv) ImportFunc(module, field string, sig abi.Sig) (variadic bool, absAddr uint64, err error) {
	return
}

func (*dummyEnv) ImportGlobal(module, field string, t abi.Type) (valueBits uint64, err error) {
	return
}

var loadBenchmarkEnv Env = new(dummyEnv)

const (
	loadBenchmarkFilename      = "../testdata/large.wasm"
	loadBenchmarkEntrySymbol   = "run"
	loadBenchmarkEntryNumArgs  = 2
	loadBenchmarkMaxTextSize   = 16 * 1024 * 1024
	loadBenchmarkMaxDataSize   = 16 * 1024 * 1024
	loadBenchmarkMaxRODataSize = 16 * 1024 * 1024
	loadBenchmarkRODataAddr    = 0x10000
	loadBenchmarkTextCRC32     = 0x5e8971b3
	loadBenchmarkRODataCRC32   = 0xc4e3c183
	loadBenchmarkIgnoreCRC32   = false
)

func BenchmarkLoad(b *testing.B)              { benchmarkLoad(b) }
func BenchmarkLoadSections(b *testing.B)      { benchmarkLoadSections(b, nil) }
func BenchmarkLoadEventSections(b *testing.B) { benchmarkLoadSections(b, func(event.Event) {}) }

func benchmarkLoad(b *testing.B) {
	b.Helper()

	wasm, err := ioutil.ReadFile(loadBenchmarkFilename)
	if err != nil {
		b.Fatal(err)
	}

	text := make([]byte, loadBenchmarkMaxTextSize)
	roData := make([]byte, loadBenchmarkMaxRODataSize)

	b.StopTimer()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m := Module{
			EntrySymbol: loadBenchmarkEntrySymbol,
			EntryArgs:   make([]uint64, loadBenchmarkEntryNumArgs),
		}

		r := bytes.NewReader(wasm)
		textBuf := static.Buf(text)
		roDataBuf := static.Buf(roData)

		b.StartTimer()
		m.load(r, loadBenchmarkEnv, textBuf, roDataBuf, loadBenchmarkRODataAddr, nil, nil)
		b.StopTimer()

		checkLoadBenchmarkOutput(b, textBuf, roDataBuf)
	}
}

func benchmarkLoadSections(b *testing.B, eventHandler func(event.Event)) {
	b.Helper()

	wasm, err := ioutil.ReadFile(loadBenchmarkFilename)
	if err != nil {
		b.Fatal(err)
	}

	text := make([]byte, loadBenchmarkMaxTextSize)
	roData := make([]byte, loadBenchmarkMaxRODataSize)
	data := make([]byte, loadBenchmarkMaxDataSize)

	var (
		elapPre  testDuration
		elapCode testDuration
		elapData testDuration
	)

	b.StopTimer()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m := Module{
			EntrySymbol: loadBenchmarkEntrySymbol,
			EntryArgs:   make([]uint64, loadBenchmarkEntryNumArgs),
		}

		r := bytes.NewReader(wasm)
		textBuf := static.Buf(text)
		roDataBuf := static.Buf(roData)
		dataBuf := static.Buf(data)

		b.StartTimer()

		t0 := time.Now()
		m.loadPreliminarySections(r, loadBenchmarkEnv)
		t1 := time.Now()
		m.loadCodeSection(r, textBuf, roDataBuf, loadBenchmarkRODataAddr, nil, eventHandler)
		t2 := time.Now()
		m.loadDataSection(r, dataBuf)
		t3 := time.Now()

		b.StopTimer()

		elapPre.set(t1.Sub(t0))
		elapCode.set(t2.Sub(t1))
		elapData.set(t3.Sub(t2))

		checkLoadBenchmarkOutput(b, textBuf, roDataBuf)
	}

	b.Logf("pre:  %v", elapPre)
	b.Logf("code: %v", elapCode)
	b.Logf("data: %v", elapData)
}

func checkLoadBenchmarkOutput(b *testing.B, textBuf, roDataBuf *static.Buffer) {
	b.Helper()

	sum := crc32.ChecksumIEEE(textBuf.Bytes())
	if sum != loadBenchmarkTextCRC32 && !loadBenchmarkIgnoreCRC32 {
		b.Errorf("text checksum changed: 0x%08x", sum)
	}

	sum = crc32.ChecksumIEEE(roDataBuf.Bytes())
	if sum != loadBenchmarkRODataCRC32 && !loadBenchmarkIgnoreCRC32 {
		b.Errorf("rodata checksum changed: 0x%08x", sum)
	}
}

func TestBenchmarkRunNqueens(t *testing.T) {
	if !testing.Verbose() {
		t.SkipNow()
	}

	const (
		filename = "../testdata/nqueens.wasm"

		maxTextSize   = 65536
		maxRODataSize = 4096
		stackSize     = 65536

		dumpText = false
	)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	p, err := runner.NewProgram(maxTextSize, maxRODataSize)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	m := Module{
		EntrySymbol:     "benchmark_main",
		MemoryAlignment: os.Getpagesize(),
	}
	m.load(bytes.NewReader(data), runner.Env, static.Buf(p.Text), static.Buf(p.ROData), p.FixedRODataAddr(), nil, &p.ObjInfo)
	p.Seal()
	p.SetData(m.Data())
	minMemorySize, maxMemorySize := m.MemoryLimits()

	if dumpText && testing.Verbose() {
		dump.Text(os.Stdout, m.Text(), p.TextAddr(), p.RODataAddr(), p.ObjInfo.FuncAddrs, nil)
	}

	r, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var printBuf bytes.Buffer
	result, err := r.Run(0, m.Sigs(), &printBuf)
	if err != nil {
		t.Fatal(err)
	}
	if result < 0 {
		t.Error("TSC measurement out of range")
	} else {
		t.Logf("%d measures (%.2fx standalone)", result, float64(result)/123456789)
	}
}
