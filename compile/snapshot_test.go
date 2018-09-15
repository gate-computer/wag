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

		dumpBin  = false
		dumpText = false
	)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	wasmReadCloser := wast2wasm(data, false)
	defer wasmReadCloser.Close()
	wasm := bufio.NewReader(wasmReadCloser)

	p, err := runner.NewProgram(maxTextSize, maxRODataSize)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	m := Module{EntrySymbol: "main"}
	m.load(wasm, runner.Env, static.Buf(p.Text), static.Buf(p.ROData), p.FixedRODataAddr(), nil, &p.ObjInfo)
	p.Seal()
	p.SetData(m.Data())
	minMemorySize, maxMemorySize := m.MemoryLimits()

	if dumpBin {
		if err := writeBin(&m, filename); err != nil {
			t.Error(err)
		}
	}

	if dumpText && testing.Verbose() {
		dump.Text(os.Stdout, m.Text(), p.TextAddr(), p.RODataAddr(), p.ObjInfo.FuncAddrs, nil)
	}

	var printBuf bytes.Buffer

	r1, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r1.Run(0, m.Sigs(), &printBuf)
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
	_, err = r2.Run(0, m.Sigs(), &printBuf)
	r2.Close()

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", string(printBuf.Bytes()))
	}

	if len(r2.Snapshots) != 0 {
		t.Fatal(r2.Snapshots)
	}
}
