// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build debug || gendebug

package debug

import (
	"fmt"
)

const Enabled = true

var Depth int

func Printf(format string, args ...interface{}) {
	if Depth < 0 {
		panic("negative DebugDepth")
	}

	for i := 0; i < Depth; i++ {
		print("  ")
	}

	print(fmt.Sprintf(format+"\n", args...))
}
