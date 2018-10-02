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
	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/static"
)

func TestExec(t *testing.T) {
	const (
		filename = "../testdata/exec.wast"

		maxTextSize = 65536
		stackSize   = 4096

		dumpText = false
	)

	wasmData, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	wasmReadCloser := wast2wasm(wasmData, false)
	defer wasmReadCloser.Close()
	wasm := bufio.NewReader(wasmReadCloser)

	mod := loadInitialSections(&ModuleConfig{}, wasm)
	bindVariadicImports(mod, runner.Resolver)

	var codeBuf bytes.Buffer

	if n, err := section.CopyKnownSection(&codeBuf, wasm, section.Code, nil); err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("not a code section")
	}

	minMemorySize := mod.InitialMemorySize()
	maxMemorySize := mod.MemorySizeLimit()

	entryFunc := findNiladicEntryFunc(mod, "main")

	p, err := runner.NewProgram(maxTextSize, entryFunc, nil)
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
	e, eventHandler := r.NewExecutor(mod.Types(), &printBuf)

	var data = &DataConfig{}
	loadDataSection(data, wasm, mod)
	p.SetData(data.GlobalsMemory.Bytes(), mod.GlobalsSize())

	var code = &CodeConfig{
		Text:         static.Buf(p.Text),
		Map:          &p.DebugMap,
		EventHandler: eventHandler,
		LastInitFunc: entryFunc,
	}
	loadCodeSection(code, &codeBuf, mod)
	p.Seal()
	if _, err := e.Wait(); err != nil {
		t.Fatal(err)
	}

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", string(printBuf.Bytes()))
	}

	if dumpText && testing.Verbose() {
		dump.Text(os.Stdout, code.Text.Bytes(), p.TextAddr(), &p.DebugMap, nil)
	}
}
