// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object

import (
	"testing"
	"unsafe"
)

func TestCallSite(*testing.T) {
	var x CallSite

	if unsafe.Sizeof(x) != 8 {
		panic("CallSite has wrong size")
	}

	if unsafe.Offsetof(x.RetAddr) != 0 {
		panic("CallSite.RetAddr is at wrong offset")
	}

	if unsafe.Offsetof(x.StackOffset) != 4 {
		panic("CallSite.RetAddr is at wrong offset")
	}

	var array [1]CallSite

	if unsafe.Sizeof(array) != 8 {
		panic("CallSite array has wrong size")
	}
}
