// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package library

import (
	"bufio"
	"os"

	"gate.computer/wag/internal/loader"
)

type L interface {
	LoadSections(r loader.Loader) (err error)
	NumImportFuncs() int
	SetImportFunc(i int, vectorIndex int)
}

func Load(filename string, dummyBinding bool, loadLibrary func(*loader.L) L) L {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	load := loader.New(bufio.NewReader(f), 0)
	lib := loadLibrary(load)

	if dummyBinding {
		for i := 0; i < lib.NumImportFuncs(); i++ {
			lib.SetImportFunc(i, i-1000)
		}
	}

	if err := lib.LoadSections(load); err != nil {
		panic(err)
	}

	return lib
}
