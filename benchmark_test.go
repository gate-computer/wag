// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"math"
	"os"
	"runtime"
	"testing"

	"gate.computer/wag/buffer"
	"gate.computer/wag/internal/test/runner"
	"gate.computer/wag/object/debug/dump"
)

func TestBenchmarkRunNqueens(t *testing.T) {
	if !testing.Verbose() {
		t.SkipNow()
	}

	const (
		filename = "testdata/nqueens.wasm"

		maxTextSize = 65536
		stackSize   = 65536

		dumpText = false
	)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	p, err := runner.NewProgram(maxTextSize, math.MaxUint32, math.MaxUint32)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	config := Config{
		Text:            buffer.NewStatic(p.Text[:0:len(p.Text)]),
		MemoryAlignment: os.Getpagesize(),
		Entry:           "benchmark_main",
	}

	obj, err := Compile(&config, bytes.NewReader(data), lib)
	if err != nil {
		t.Fatal(err)
	}
	p.SetEntryAddr(uint32(binary.LittleEndian.Uint64(obj.StackFrame)))
	p.Seal()
	p.SetData(obj.GlobalsMemory, obj.MemoryOffset)

	if dumpText && testing.Verbose() {
		dump.Text(os.Stdout, obj.Text, p.TextAddr(), obj.FuncAddrs, &obj.Names)
	}

	r, err := p.NewRunner(obj.InitialMemorySize, obj.MemorySizeLimit, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var printBuf bytes.Buffer
	result, err := r.Run(0, nil, &printBuf)
	if err != nil {
		t.Fatal(err)
	}
	if result < 0 {
		t.Error("TSC measurement out of range")
	} else {
		t.Logf("%d measures (%.2fx standalone)", result, float64(result)/123456789)
	}
}
