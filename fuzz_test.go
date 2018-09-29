// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"bufio"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/tsavola/wag/internal/test/runner"
	"github.com/tsavola/wag/static"
)

const (
	fuzzInputDir = "../testdata/fuzz/corpus"
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
			fuzz(t, path.Join(fuzzInputDir, info.Name()))
		}
	}
}

func fuzz(t *testing.T, filename string) {
	const (
		maxTextSize = 65536
		stackSize   = 4096
	)

	p, err := runner.NewProgram(maxTextSize)
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

	var ok bool

	defer func() {
		if !ok {
			t.Logf("%s: panic", filename)
		}
	}()

	config := Config{
		Text: static.Buf(p.Text),
	}

	_, err = Compile(&config, bufio.NewReader(f), runner.Resolver)
	if err == nil {
		t.Logf("%s: no error", filename)
	} else {
		t.Logf("%s: %v", filename, err)
	}

	ok = true
}
