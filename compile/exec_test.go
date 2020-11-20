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
	"gate.computer/wag/section"
)

func TestExec(t *testing.T) {
	const (
		filename = "../testdata/exec.wat"

		maxTextSize = 65536
		stackSize   = 16384

		dumpText = false
	)

	wasmData, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	wasmReadCloser := wat.ToWasm("../testdata", wasmData, false)
	defer wasmReadCloser.Close()
	wasm := bufio.NewReader(wasmReadCloser)

	mod := loadInitialSections(nil, wasm)
	bind(&mod, lib, nil)

	var codeBuf bytes.Buffer

	if n, err := section.CopyStandardSection(&codeBuf, wasm, section.Code, nil); err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("not a code section")
	}

	minMemorySize := mod.InitialMemorySize()
	maxMemorySize := mod.MemorySizeLimit()

	startFunc, defined := mod.StartFunc()
	if !defined {
		startFunc = math.MaxUint32
	}

	entryFunc := findNiladicEntryFunc(mod, "main")

	p, err := runner.NewProgram(maxTextSize, startFunc, entryFunc)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	r, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var printBuf bytes.Buffer
	e, eventHandler := r.NewExecutor(lib.l.Types, &printBuf)

	var data = &DataConfig{}
	loadDataSection(data, wasm, mod)
	p.SetData(data.GlobalsMemory.Bytes(), mod.GlobalsSize())

	codeReader := debug.NewReadTeller(&codeBuf)
	var code = &CodeConfig{
		Text:         buffer.NewStatic(p.Text[:0:len(p.Text)]),
		Mapper:       p.DebugMap.Mapper(codeReader),
		EventHandler: eventHandler,
		LastInitFunc: entryFunc,
	}
	loadCodeSection(code, codeReader, mod, &lib.l)
	p.Seal()
	if _, err := e.Wait(); err != nil {
		t.Error(err)
	}

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", printBuf.String())
	}

	if dumpText && testing.Verbose() {
		dump.Text(os.Stdout, code.Text.Bytes(), p.TextAddr(), p.DebugMap.FuncAddrs, nil)
	}
}
