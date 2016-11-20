package wag

import (
	"bufio"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/tsavola/wag/runner"
)

const (
	fuzzInputDir = "testdata/fuzz/corpus"
)

func TestFuzz(t *testing.T) {
	infos, err := ioutil.ReadDir(fuzzInputDir)
	if err != nil {
		if os.IsNotExist(err) {
			t.Log(err)
			return
		}
		t.Fatal(err)
	}

	for _, info := range infos {
		if !strings.Contains(info.Name(), ".") {
			testFuzz(t, path.Join(fuzzInputDir, info.Name()))
		}
	}
}

func testFuzz(t *testing.T, filename string) {
	const (
		maxTextSize   = 65536
		maxRODataSize = 4096
		stackSize     = 4096
	)

	p, err := runner.NewProgram(maxTextSize, maxRODataSize)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	f, err := os.Open(filename)
	if err != nil {
		t.Errorf("%s: %v", filename, err)
		return
	}
	defer f.Close()

	var m Module
	var ok bool

	defer func() {
		if !ok {
			t.Logf("%s: panic", filename)
		}
	}()

	err = m.Load(bufio.NewReader(f), runner.Env, p.Text, p.ROData, p.RODataAddr(), nil)
	if err == nil {
		t.Logf("%s: no error", filename)
	} else {
		t.Logf("%s: %v", filename, err)
	}

	ok = true
}
