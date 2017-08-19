// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sections

import (
	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/reader"
)

type FunctionName struct {
	FunName    string
	LocalNames []string
}

type NameSection struct {
	FunctionNames []FunctionName
}

// Load old "name" section encoding, as encoded by wabt.
func (ns *NameSection) Load(_ string, r reader.Reader) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	load := loader.L{r}

	count := load.Varuint32()
	ns.FunctionNames = make([]FunctionName, count)

	for i := range ns.FunctionNames {
		fn := &ns.FunctionNames[i]

		funNameLen := load.Varuint32()
		fn.FunName = string(load.Bytes(funNameLen))

		localCount := load.Varuint32()
		fn.LocalNames = make([]string, localCount)

		for j := range fn.LocalNames {
			localNameLen := load.Varuint32()
			fn.LocalNames[j] = string(load.Bytes(localNameLen))
		}
	}

	return
}
