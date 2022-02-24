// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !((debug || indebug) && cgo)
// +build !debug,!indebug !cgo

package in

var debugPrinted bool

func debugPrintInsn([]byte) {
	if !debugPrinted {
		println("wag/internal/isa/amd64/in: debugPrintIn called in non-debug build")
		debugPrinted = true
	}
}
