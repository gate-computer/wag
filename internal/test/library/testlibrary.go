// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package library

import (
	"bufio"
	"os"

	"gate.computer/wag/binary"
)

type L interface {
	LoadSections(r binary.Reader) (err error)
	NumImportFuncs() int
	SetImportFunc(i int, vectorIndex int)
}

func Load(filename string, dummyBinding bool, loadLibrary func(r binary.Reader) L) L {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	lib := loadLibrary(r)

	if dummyBinding {
		for i := 0; i < lib.NumImportFuncs(); i++ {
			lib.SetImportFunc(i, i-1000)
		}
	}

	if err := lib.LoadSections(r); err != nil {
		panic(err)
	}

	return lib
}
