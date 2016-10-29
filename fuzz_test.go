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
	fuzzInputDir = "testdata/fuzz/crashers"
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
	t.Log(filename)

	const (
		maxTextSize   = 65536
		maxRODataSize = 4096
		stackSize     = 4096
	)

	f, err := os.Open(filename)
	if err != nil {
		t.Errorf("%s: %v", filename, err)
		return
	}
	defer f.Close()

	p, err := runner.NewProgram(maxTextSize, maxRODataSize)
	if err != nil {
		t.Errorf("%s: %v", filename, err)
		return
	}
	defer p.Close()

	var m Module

	err = m.Load(bufio.NewReader(f), runner.Env, p.Text, p.ROData, p.RODataAddr(), nil)
	if err != nil {
		t.Log(err)
	}
}
