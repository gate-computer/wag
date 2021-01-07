// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package library

import (
	"bufio"
	"io/ioutil"
	"path"

	"gate.computer/wag/binary"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/test/wat"
	"gate.computer/wag/wa"
)

type Library interface {
	LoadSections(r binary.Reader) (err error)
	NumImportFuncs() int
	ImportFunc(i int) (module, field string, sig wa.FuncType)
	SetImportFunc(i int, vectorIndex int)
	XXX_Internal() interface{}
}

type VectorResolver interface {
	ResolveFunc(module, field string, sig wa.FuncType) (vectorIndex int, err error)
}

func bindVector(lib Library, reso VectorResolver) {
	for i := 0; i < lib.NumImportFuncs(); i++ {
		index, err := reso.ResolveFunc(lib.ImportFunc(i))
		if err != nil {
			panic(err)
		}
		lib.SetImportFunc(i, index)
	}
}

type VariadicResolver interface {
	ResolveVariadicFunc(module, field string, sig wa.FuncType) (variadic bool, index int, err error)
}

func bindVariadic(lib Library, reso VariadicResolver) {
	var err error

	for i := 0; i < lib.NumImportFuncs(); i++ {
		imp := &lib.XXX_Internal().(*module.Library).ImportFuncs[i]
		imp.Variadic, imp.VectorIndex, err = reso.ResolveVariadicFunc(lib.ImportFunc(i))
		if err != nil {
			panic(err)
		}
	}
}

func Load(testdatadir string, reso VectorResolver, loadInitialLibrary func(r binary.Reader) Library) Library {
	source, err := ioutil.ReadFile(path.Join(testdatadir, "library.wat"))
	if err != nil {
		panic(err)
	}

	rc := wat.ToWasm(testdatadir, source, false)
	defer rc.Close()

	r := bufio.NewReader(rc)

	lib := loadInitialLibrary(r)

	if x, ok := reso.(VariadicResolver); ok {
		bindVariadic(lib, x)
	} else {
		bindVector(lib, reso)
	}

	if err := lib.LoadSections(r); err != nil {
		panic(err)
	}

	return lib
}
