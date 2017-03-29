package wag

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/tsavola/wag/dewag"
	"github.com/tsavola/wag/runner"
	"github.com/tsavola/wag/sections"
)

func TestExec(t *testing.T) {
	const (
		filename = "testdata/exec.wast"

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

	m := Module{MainSymbol: "main"}
	m.loadPreliminarySections(wasm, runner.Env)

	var codeBuf bytes.Buffer

	if ok, err := sections.CopyCodeSection(&codeBuf, wasm); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal(ok)
	}

	// skip name section
	if err := sections.DiscardUnknownSections(wasm); err != nil {
		t.Fatal(err)
	}

	minMemorySize, maxMemorySize := m.MemoryLimits()

	p, err := runner.NewProgram(maxTextSize, maxRODataSize)
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
	e, trigger := r.NewExecutor(m.Signatures(), &printBuf)

	m.loadDataSection(wasm)
	p.SetData(m.Data())
	m.loadCodeSection(&codeBuf, bytes.NewBuffer(p.Text[:0]), p.ROData, p.RODataAddr(), trigger)
	p.Seal()
	p.SetFunctionMap(m.FunctionMap())
	p.SetCallMap(m.CallMap())
	if _, err := e.Wait(); err != nil {
		t.Fatal(err)
	}

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", string(printBuf.Bytes()))
	}

	if dumpBin {
		if err := writeBin(&m, filename); err != nil {
			t.Error(err)
		}
	}

	if dumpText && testing.Verbose() {
		dewag.PrintTo(os.Stdout, m.Text(), m.FunctionMap(), nil)
	}
}
