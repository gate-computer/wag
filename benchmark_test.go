// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/tsavola/wag/dewag"
	"github.com/tsavola/wag/internal/test/runner"
	"github.com/tsavola/wag/types"
)

type testDuration struct {
	time.Duration
}

func (target *testDuration) set(d time.Duration) {
	if target.Duration <= 0 || d < target.Duration {
		target.Duration = d
	}
}

func makeNoTrigger() chan struct{} { return nil }
func makeTrigger() chan struct{}   { return make(chan struct{}) }

type dummyEnv struct{}

func (*dummyEnv) ImportFunction(module, field string, sig types.Function) (variadic bool, absAddr uint64, err error) {
	return
}

func (*dummyEnv) ImportGlobal(module, field string, t types.T) (valueBits uint64, err error) {
	return
}

var loadBenchmarkEnv Environment = new(dummyEnv)

const (
	loadBenchmarkFilename      = "testdata/large.wasm"
	loadBenchmarkEntrySymbol   = "run"
	loadBenchmarkEntryNumArgs  = 2
	loadBenchmarkMaxTextSize   = 16 * 1024 * 1024
	loadBenchmarkMaxDataSize   = 16 * 1024 * 1024
	loadBenchmarkMaxRODataSize = 4096
	loadBenchmarkRODataAddr    = 0x10000
	loadBenchmarkTextSum       = "dea5d76345f70be24fc3f28b3baf52b5c03401c4009c87cdc6d1f609e525b35e"
	loadBenchmarkRODataSum     = "ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7"
)

func BenchmarkLoad(b *testing.B)                { benchmarkLoad(b) }
func BenchmarkLoadSections(b *testing.B)        { benchmarkLoadSections(b, makeNoTrigger) }
func BenchmarkLoadTriggerSections(b *testing.B) { benchmarkLoadSections(b, makeTrigger) }

func benchmarkLoad(b *testing.B) {
	b.Helper()

	wasm, err := ioutil.ReadFile(loadBenchmarkFilename)
	if err != nil {
		b.Fatal(err)
	}

	text := make([]byte, 0, loadBenchmarkMaxTextSize)
	roData := make([]byte, loadBenchmarkMaxRODataSize)

	b.StopTimer()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m := Module{
			EntrySymbol: loadBenchmarkEntrySymbol,
			EntryArgs:   make([]uint64, loadBenchmarkEntryNumArgs),
		}

		r := bytes.NewReader(wasm)
		textBuf := bytes.NewBuffer(text)

		b.StartTimer()
		m.load(r, loadBenchmarkEnv, textBuf, roData, loadBenchmarkRODataAddr, nil)
		b.StopTimer()

		checkLoadBenchmarkOutput(b, textBuf, roData)
	}
}

func benchmarkLoadSections(b *testing.B, makeOptionalTrigger func() chan struct{}) {
	b.Helper()

	wasm, err := ioutil.ReadFile(loadBenchmarkFilename)
	if err != nil {
		b.Fatal(err)
	}

	text := make([]byte, 0, loadBenchmarkMaxTextSize)
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
		textBuf := bytes.NewBuffer(text)
		trigger := makeOptionalTrigger()

		b.StartTimer()

		t0 := time.Now()
		m.loadPreliminarySections(r, loadBenchmarkEnv)
		t1 := time.Now()
		m.loadCodeSection(r, textBuf, roData, loadBenchmarkRODataAddr, trigger)
		t2 := time.Now()
		m.loadDataSection(r, data)
		t3 := time.Now()

		b.StopTimer()

		elapPre.set(t1.Sub(t0))
		elapCode.set(t2.Sub(t1))
		elapData.set(t3.Sub(t2))

		checkLoadBenchmarkOutput(b, textBuf, roData)
	}

	b.Logf("pre:  %v", elapPre)
	b.Logf("code: %v", elapCode)
	b.Logf("data: %v", elapData)
}

func checkLoadBenchmarkOutput(b *testing.B, textBuf *bytes.Buffer, roData []byte) {
	b.Helper()

	if textBuf.Len() > loadBenchmarkMaxTextSize {
		b.Errorf("loadBenchmarkMaxTextSize is too small (text size is %d)", textBuf.Len())
	}

	sum := sha256.Sum256(textBuf.Bytes())
	textSum := hex.EncodeToString(sum[:])
	if textSum != loadBenchmarkTextSum {
		b.Errorf("text checksum changed: %s", textSum)
	}

	sum = sha256.Sum256(roData)
	roDataSum := hex.EncodeToString(sum[:])
	if roDataSum != loadBenchmarkRODataSum {
		b.Errorf("read-only data checksum changed: %s", roDataSum)
	}
}

func TestBenchmarkRunNqueens(t *testing.T) {
	if !testing.Verbose() {
		t.SkipNow()
	}

	const (
		filename = "testdata/nqueens.wasm"

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
	m.load(bytes.NewReader(data), runner.Env, bytes.NewBuffer(p.Text[:0]), p.ROData, p.RODataAddr(), nil)
	p.Seal()
	p.SetData(m.Data())
	p.SetFunctionMap(m.FunctionMap())
	p.SetCallMap(m.CallMap())
	minMemorySize, maxMemorySize := m.MemoryLimits()

	r, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var printBuf bytes.Buffer
	result, err := r.Run(0, m.Signatures(), &printBuf)
	if err != nil {
		t.Fatal(err)
	}
	if result < 0 {
		t.Error("TSC measurement out of range")
	} else {
		t.Logf("%d measures (%.2fx standalone)", result, float64(result)/123456789)
	}

	if dumpText && testing.Verbose() {
		dewag.PrintTo(os.Stdout, m.Text(), m.FunctionMap(), nil)
	}
}
