// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuzz

import (
	"bytes"
	"fmt"

	"github.com/bnagy/gapstone"

	"github.com/tsavola/wag"
	"github.com/tsavola/wag/abi"
)

const (
	roDataAddr = 0x10000
)

func Fuzz(data []byte) int {
	obj, err := wag.Compile(&wag.Config{RODataAddr: roDataAddr}, bytes.NewReader(data), res{})
	if err != nil {
		return 0
	}

	if len(obj.Text) != 0 {
		engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
		if err != nil {
			panic(err)
		}
		defer engine.Close()

		_, err = engine.Disasm(obj.Text, 0, 0)
		if err != nil {
			panic(err)
		}
	}

	return 1
}

type res struct{}

func (res) ResolveFunc(module, field string, sig abi.Sig) (addr uint64, err error) {
	err = fmt.Errorf("import function %#v%#v %s", module, field, sig)
	return
}

func (res) ResolveGlobal(module, field string, t abi.Type) (init uint64, err error) {
	err = fmt.Errorf("import %s global %#v %#v", t, module, field)
	return
}
