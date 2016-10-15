package wag

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/tsavola/wag/runner"
)

func TestExec(t *testing.T) {
	const (
		maxTextSize   = 65536
		maxRODataSize = 4096
		stackSize     = 4096
	)

	data, err := ioutil.ReadFile("testdata/exec.wast")
	if err != nil {
		t.Fatal(err)
	}

	wasmReadCloser := wast2wasm(data, false)
	defer wasmReadCloser.Close()
	wasm := bufio.NewReader(wasmReadCloser)

	var m Module
	m.loadPreliminarySections(wasm, runner.Env)

	var codeBuf bytes.Buffer
	copyCodeSection(&codeBuf, wasm)

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
	m.loadCodeSection(&codeBuf, p.Text, p.ROData, p.RODataAddr(), trigger)
	p.Seal()
	p.SetFunctionMap(m.FunctionMap())
	p.SetCallMap(m.CallMap())
	if _, err := e.Wait(); err != nil {
		t.Fatal(err)
	}

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", string(printBuf.Bytes()))
	}

	objdump(m.Text())
}
