// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package typeutil

import (
	"fmt"

	"github.com/tsavola/wag/wasm"
)

var valueTypes = []wasm.Type{
	wasm.I32,
	wasm.I64,
	wasm.F32,
	wasm.F64,
}

func ValueTypeByEncoding(x int8) wasm.Type {
	if i := uint(-1 - x); i < uint(len(valueTypes)) {
		return valueTypes[i]
	}
	panic(fmt.Errorf("unknown value type %d", x))
}

func BlockTypeByEncoding(x int8) (t wasm.Type) {
	if x == -0x40 { // empty block type
		return
	}
	if i := uint(-1 - x); i < uint(len(valueTypes)) {
		return valueTypes[i]
	}
	panic(fmt.Errorf("unknown block type %d", x))
}
