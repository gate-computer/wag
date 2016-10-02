package wag

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/tsavola/wag/internal/sexp"
	"github.com/tsavola/wag/runner"
)

func TestExec(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/exec.wast")
	if err != nil {
		t.Fatal(err)
	}

	expr, _ := sexp.ParsePanic(data)
	if expr == nil {
		t.Fatal()
	}

	m := loadModule(expr)
	globals, data := m.Data()

	const (
		maxRODataSize = 4096
		stackSize     = 4096
	)

	b, err := runner.NewBuffer(maxTextSize, maxRODataSize)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	p := b.NewProgram(globals, data, m.FuncTypes(), m.FuncNames())

	r, err := p.NewRunner(m.Memory.MinSize, m.Memory.MaxSize, stackSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var printBuf bytes.Buffer

	e, trigger := r.NewExecutor(0, m.ImportTypes(), &printBuf)
	_, _, funcMap, callMap := m.Code(runner.Imports, b.Text, b.RODataAddr(), b.ROData, trigger)
	b.Seal()
	p.SetMaps(funcMap, callMap)
	result, err := e.Wait()

	if printBuf.Len() > 0 {
		t.Logf("print output:\n%s", string(printBuf.Bytes()))
	}

	if result != 12345 {
		t.Fatal(result)
	}
}
