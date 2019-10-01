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

	"github.com/tsavola/wag/internal/test/fuzz/fuzzutil"
)

func TestFuzz(t *testing.T) {
	dir := os.Getenv("WAG_TEST_FUZZ")
	if dir == "" {
		t.Skip("WAG_TEST_FUZZ directory not set")
	}

	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var tested bool

	for _, info := range infos {
		if !strings.Contains(info.Name(), ".") {
			filename := path.Join(dir, info.Name())

			t.Run(info.Name(), func(t *testing.T) {
				if testing.Verbose() {
					println(filename)
				} else {
					t.Parallel()
				}

				fuzzCorpusTest(t, filename)
			})

			tested = true
		}
	}

	if !tested {
		t.Logf("%s does not contain any samples", dir)
	}
}

func fuzzCorpusTest(t *testing.T, filename string) {
	t.Helper()

	var ok bool

	defer func() {
		if !ok {
			t.Fail()
		}
	}()

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
		Text:          fuzzutil.NewTextBuffer(),
		GlobalsMemory: fuzzutil.NewGlobalsMemoryBuffer(),
	}

	_, err = Compile(config, bytes.NewReader(data), lib)
	if err != nil {
		if fuzzutil.IsFine(err) {
			t.Log(err)
		} else {
			t.Fatal(err)
		}
	}

	ok = true
}
