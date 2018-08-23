// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package meta

// TextAddr represents a non-negative offset from the start of the text section
// (machine code).
type TextAddr int32

// CallSite represents a position within the text section (machine code) where
// a function call is made.
type CallSite struct {
	ReturnAddr  TextAddr // The address immediately after the call instruction
	StackOffset int32    // Calling function's stack usage at time of call
}

// InsnMap accepts information about positions of functions and instructions
// (WebAssembly) within the text section (machine code).
type InsnMap interface {
	Init(numFuncs int)
	PutFunc(TextAddr)
	PutInsn(TextAddr)
}
