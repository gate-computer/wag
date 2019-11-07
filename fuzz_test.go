// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/tsavola/wag/internal/test/fuzzutil"
)

func TestFuzzCorpus(t *testing.T)   { testFuzzDir(t, "testdata/fuzz/corpus") }
func TestFuzzCrashers(t *testing.T) { testFuzzDir(t, "testdata/fuzz/crashers") }

func testFuzzDir(t *testing.T, dir string) {
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}

	var tested bool

	for _, info := range infos {
		if !strings.Contains(info.Name(), ".") {
			filename := path.Join(dir, info.Name())

			t.Run(info.Name(), func(t *testing.T) {
				t.Parallel()
				testFuzzFile(t, filename)
			})

			tested = true
		}
	}

	if !tested {
		t.Skipf("%s does not contain any samples", dir)
	}
}

func testFuzzFile(t *testing.T, filename string) {
	t.Helper()

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
		ImportResolver: fuzzutil.Resolver{Lib: lib},
		Text:           fuzzutil.NewTextBuffer(),
		GlobalsMemory:  fuzzutil.NewGlobalsMemoryBuffer(),
	}

	_, err = Compile(config, bytes.NewReader(data), lib)
	if _, ok := fuzzutil.Result(err); !ok {
		t.Error(err)
	}
}
