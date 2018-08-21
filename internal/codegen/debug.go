// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"
)

const (
	debug = false
)

var (
	debugDepth int
)

func debugf(format string, args ...interface{}) {
	if debugDepth < 0 {
		panic("negative debugDepth")
	}

	if debug {
		for i := 0; i < debugDepth; i++ {
			fmt.Print("  ")
		}

		fmt.Printf(format+"\n", args...)
	}
}
