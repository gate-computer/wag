// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"math"
	"os"
	"testing"

	"gate.computer/wag/buffer"
	"gate.computer/wag/internal/test/runner"
	"gate.computer/wag/internal/test/wat"
	"gate.computer/wag/object/debug"
	"gate.computer/wag/object/debug/dump"
)

func TestSnapshot(t *testing.T) {
	const (
		filename = "../testdata/snapshot.wat"

		maxTextSize = 65536
		stackSize   = 16384

		dumpText = false
	)

	wasmData, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	wasmReadCloser := wat.ToWasm(wasmData, false)
	defer wasmReadCloser.Close()
	wasm := bufio.NewReader(wasmReadCloser)

	mod := loadInitialSections(nil, wasm)
	bind(&mod, lib, nil)

	p, err := runner.NewProgram(maxTextSize, math.MaxUint32, findNiladicEntryFunc(mod, "main"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	codeReader := debug.NewReadTeller(wasm)
	var code = &CodeConfig{
		Text:   buffer.NewStatic(p.Text[:0:len(p.Text)]),
		Mapper: p.DebugMap.Mapper(codeReader),
	}
	loadCodeSection(code, codeReader, mod, &lib.l)

	var data = &DataConfig{}
	loadDataSection(data, wasm, mod)

	p.Seal()
	p.SetData(data.GlobalsMemory.Bytes(), mod.GlobalsSize())
	minMemorySize := mod.InitialMemorySize()
	maxMemorySize := mod.MemorySizeLimit()

	if dumpText && testing.Verbose() {
		dump.Text(os.Stdout, code.Text.Bytes(), p.TextAddr(), p.DebugMap.FuncAddrs, nil)
	}

	var printBuf bytes.Buffer

	r1, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r1.Run(0, lib.l.Types, &printBuf)
	r1.Close()
	if err != nil {
		t.Fatal(err)
	}

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", printBuf.String())
	}

	if len(r1.Snapshots) != 1 {
		t.Fatal(r1.Snapshots)
	}
	s := r1.Snapshots[0]

	t.Log("resuming")

	printBuf.Reset()

	r2, err := s.NewRunner(p, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Run(0, lib.l.Types, &printBuf); err != nil {
		t.Error(err)
	}
	r2.Close()

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", printBuf.String())
	}

	if len(r2.Snapshots) != 0 {
		t.Error(r2.Snapshots)
	}
}
