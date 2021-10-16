// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(debug || gendebug)
// +build !debug,!gendebug

package debug

const Enabled = false

var Depth int

func Printf(string, ...interface{}) {
	panic("debug.Printf called without debug.Enabled")
}
