package wag

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/tsavola/wag/dewag"
	"github.com/tsavola/wag/runner"
)

func TestSnapshot(t *testing.T) {
	const (
		maxTextSize   = 65536
		maxRODataSize = 4096
		stackSize     = 4096

		dumpText = false
	)

	data, err := ioutil.ReadFile("testdata/snapshot.wast")
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
	m.load(wasm, runner.Env, p.Text, p.ROData, p.RODataAddr(), nil)
	p.Seal()
	p.SetData(m.Data())
	p.SetFunctionMap(m.FunctionMap())
	p.SetCallMap(m.CallMap())
	minMemorySize, maxMemorySize := m.MemoryLimits()

	if dumpText && testing.Verbose() {
		dewag.PrintTo(os.Stdout, m.Text(), m.FunctionMap())
	}

	var printBuf bytes.Buffer

	r1, err := p.NewRunner(minMemorySize, maxMemorySize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r1.Run(0, m.Signatures(), &printBuf)
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
	_, err = r2.Run(0, m.Signatures(), &printBuf)
	r2.Close()

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", string(printBuf.Bytes()))
	}

	if len(r2.Snapshots) != 0 {
		t.Fatal(r2.Snapshots)
	}
}
