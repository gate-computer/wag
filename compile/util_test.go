// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"gate.computer/wag/internal/test/library"
	"gate.computer/wag/internal/test/runner"
	"gate.computer/wag/wa"
)

var lib = *library.Load("../testdata", runner.Resolver, func(r Reader) library.Library {
	mod := loadInitialSections(nil, r)
	lib := mod.asLibrary()
	return &lib
}).(*Library)

type globalResolver interface {
	ResolveGlobal(module, field string, t wa.Type) (init uint64, err error)
}

func bind(mod *Module, lib Library, reso globalResolver) {
	for i := 0; i < mod.NumImportFuncs(); i++ {
		_, field, modSig := mod.ImportFunc(i)

		index, libSig, found := lib.ExportFunc(field)
		if !found {
			panic(field)
		}

		if !libSig.Equal(modSig) {
			panic(modSig)
		}

		mod.SetImportFunc(i, index)
	}

	for i := 0; i < mod.NumImportGlobals(); i++ {
		init, err := reso.ResolveGlobal(mod.ImportGlobal(i))
		if err != nil {
			panic(err)
		}

		mod.SetImportGlobal(i, init)
	}
}

func findNiladicEntryFunc(mod Module, name string) (funcIndex uint32) {
	funcIndex, sig, found := mod.ExportFunc(name)
	if !found {
		panic("entry function not found")
	}
	if len(sig.Params) != 0 {
		panic("entry function has parameters")
	}
	return
}

func initFuzzCorpus(t *testing.T, filename string, r io.Reader) {
	t.Helper()

	if dir := os.Getenv("WAG_TEST_INIT_FUZZ_CORPUS"); dir != "" {
		data, err := ioutil.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		filename = path.Join(dir, filename)

		if err := ioutil.WriteFile(filename, data, 0666); err != nil {
			t.Fatal(err)
		}

		t.Skip("initializing fuzz corpus")
	}
}
