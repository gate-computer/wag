// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/tsavola/wag/internal/test/runner"
	"github.com/tsavola/wag/object/debug/dump"
	"github.com/tsavola/wag/static"
)

func TestSnapshot(t *testing.T) {
	const (
		filename = "../testdata/snapshot.wast"

		maxTextSize   = 65536
		maxRODataSize = 4096
		stackSize     = 4096

		dumpText = false
	)

	wasmData, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	wasmReadCloser := wast2wasm(wasmData, false)
	defer wasmReadCloser.Close()
	wasm := bufio.NewReader(wasmReadCloser)

	p, err := runner.NewProgram(maxTextSize, maxRODataSize)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	var mod = &Module{
		EntrySymbol: "main",
	}
	mod.loadInitialSections(wasm)
	mod.defineImports(runner.Resolver)

	var code = &CodeConfig{
		Text:         static.Buf(p.Text),
		ROData:       static.Buf(p.ROData),
		RODataAddr:   p.RODataAddr(),
		ObjectMapper: &p.ObjInfo,
	}
	loadCodeSection(code, wasm, mod)

	var data = &DataConfig{}
	loadDataSection(data, wasm, mod)

	p.Seal()
	p.SetData(data.GlobalsMemory.Bytes(), mod.GlobalsSize())
	minMemorySize, maxMemorySize := mod.MemoryLimits()

	if dumpText && testing.Verbose() {
		dump.Text(os.Stdout, code.Text.Bytes(), p.TextAddr(), p.RODataAddr(), p.ObjInfo.FuncAddrs, nil)
	}

	var printBuf bytes.Buffer

	r1, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r1.Run(0, mod.Types(), &printBuf)
	r1.Close()

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", string(printBuf.Bytes()))
	}

	if len(r1.Snapshots) != 1 {
		t.Fatal(r1.Snapshots)
	}
	s := r1.Snapshots[0]

	t.Log("resuming")

	printBuf.Reset()

	r2, err := s.NewRunner(maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r2.Run(0, mod.Types(), &printBuf)
	r2.Close()

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", string(printBuf.Bytes()))
	}

	if len(r2.Snapshots) != 0 {
		t.Fatal(r2.Snapshots)
	}
}
