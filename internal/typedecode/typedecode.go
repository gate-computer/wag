// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package typedecode

import (
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/wa"
)

var valueTypes = [4]wa.Type{
	wa.I32,
	wa.I64,
	wa.F32,
	wa.F64,
}

func Value(x int8) wa.Type {
	if i := uint(-1 - x); i < uint(len(valueTypes)) {
		return valueTypes[i]
	}
	panic(module.Errorf("unknown value type %d", x))
}

func Block(x int8) (t wa.Type) {
	if x == -0x40 { // empty block type
		return
	}
	if i := uint(-1 - x); i < uint(len(valueTypes)) {
		return valueTypes[i]
	}
	panic(module.Errorf("unknown block type %d", x))
}
