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

func TestFuzzCorpus(t *testing.T) {
	dir := os.Getenv("WAG_TEST_FUZZ_CORPUS")
	if dir == "" {
		t.Skip("WAG_TEST_FUZZ_CORPUS not set")
	}

	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var tested bool

	for _, info := range infos {
		if !strings.Contains(info.Name(), ".") {
			t.Run(info.Name(), func(t *testing.T) {
				t.Parallel()
				fuzzCorpusTest(t, path.Join(dir, info.Name()))
			})
			tested = true
		}
	}

	if !tested {
		t.Logf("%s does not contain any generated samples", dir)
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

	_, err = Compile(config, bytes.NewReader(data), fuzzutil.Resolver)
	if err != nil {
		if fuzzutil.IsFine(err) {
			t.Log(err)
		} else {
			t.Fatal(err)
		}
	}

	ok = true
}
