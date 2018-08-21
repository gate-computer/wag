// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/tsavola/wag/disasm"
	"github.com/tsavola/wag/internal/test/runner"
)

func TestCallWithDuplicatedOperand(t *testing.T) {
	misc(t, "testdata/call-with-duplicated-operand.wast", "32744 32 32\n")
}

func misc(t *testing.T, filename, expectOutput string) {
	const (
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

	var m Module
	m.load(wasm, runner.Env, NewFixedBuffer(p.Text[:0]), NewFixedBuffer(p.ROData[:0]), p.RODataAddr(), nil)
	p.Seal()
	p.SetData(m.Data())
	p.SetFunctionMap(m.FunctionMap())
	p.SetCallMap(m.CallMap())
	minMemorySize, maxMemorySize := m.MemoryLimits()

	if dumpBin {
		if err := writeBin(&m, filename); err != nil {
			t.Error(err)
		}
	}

	if dumpText && testing.Verbose() {
		disasm.Fprint(os.Stdout, m.Text(), m.FunctionMap(), nil)
	}

	var printBuf bytes.Buffer

	r, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	_, err = r.Run(0, m.Signatures(), &printBuf)
	if err != nil {
		t.Fatal(err)
	}

	output := string(printBuf.Bytes())
	t.Logf("print output:\n%s", output)
	if output != expectOutput {
		t.Fail()
	}
}
