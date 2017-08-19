// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuzz

import (
	"bytes"
	"fmt"

	"github.com/bnagy/gapstone"

	"github.com/tsavola/wag"
	"github.com/tsavola/wag/types"
)

const (
	roDataAddr = 0x10000
)

func Fuzz(data []byte) int {
	var m wag.Module

	err := m.Load(bytes.NewReader(data), env{}, nil, nil, roDataAddr, nil)
	if err != nil {
		return 0
	}

	text := m.Text()
	if len(text) != 0 {
		engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
		if err != nil {
			panic(err)
		}
		defer engine.Close()

		_, err = engine.Disasm(text, 0, 0)
		if err != nil {
			panic(err)
		}
	}

	return 1
}

type env struct{}

func (env) ImportFunction(module, field string, sig types.Function) (variadic bool, absAddr uint64, err error) {
	err = fmt.Errorf("import function %#v%#v %s", module, field, sig)
	return
}

func (env) ImportGlobal(module, field string, t types.T) (value uint64, err error) {
	err = fmt.Errorf("import %s global %#v %#v", t, module, field)
	return
}
