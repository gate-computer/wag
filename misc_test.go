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

func TestCallWithDuplicatedOperand(t *testing.T) {
	misc(t, "testdata/call-with-duplicated-operand.wast", "32744 32 32\n")
}

func misc(t *testing.T, filename, expectOutput string) {
	const (
		maxTextSize   = 65536
		maxRODataSize = 4096
		stackSize     = 4096

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
	m.load(wasm, runner.Env, p.Text, p.ROData, p.RODataAddr(), nil)
	p.Seal()
	p.SetData(m.Data())
	p.SetFunctionMap(m.FunctionMap())
	p.SetCallMap(m.CallMap())
	minMemorySize, maxMemorySize := m.MemoryLimits()

	if dumpText && testing.Verbose() {
		dewag.PrintTo(os.Stdout, m.Text(), m.FunctionMap(), nil)
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
