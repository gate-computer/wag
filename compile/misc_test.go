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

	"github.com/tsavola/wag/buffer"
	"github.com/tsavola/wag/internal/test/runner"
	"github.com/tsavola/wag/internal/test/wat"
	"github.com/tsavola/wag/object/debug/dump"
)

func TestCallWithDuplicatedOperand(t *testing.T) {
	if misc(t, "../testdata/call-with-duplicated-operand.wat", "") != "32744 32 32\n" {
		t.Fail()
	}
}

func misc(t *testing.T, filename, entry string) string {
	const (
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

	var entryFunc uint32
	if entry != "" {
		entryFunc = findNiladicEntryFunc(mod, entry)
		t.Logf("entry function index: %d", entryFunc)
	}

	p, err := runner.NewProgram(maxTextSize, entryFunc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	var code = &CodeConfig{
		Text:   buffer.NewStatic(p.Text[:0:len(p.Text)]),
		Mapper: &p.DebugMap,
	}
	loadCodeSection(code, wasm, mod, &lib.l)

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

	r, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	_, err = r.Run(0, lib.l.Types, &printBuf)
	if err != nil {
		t.Error(err)
	}

	output := printBuf.String()
	t.Logf("print output:\n%s", output)
	return output
}
