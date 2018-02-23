// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package insnmap

// Mapping from machine code instruction to WebAssembly instruction.
type Mapping struct {
	ObjectOffset int32 // Machine code byte position within a function
	SourceIndex  int32 // WebAssembly instruction count within a function
}

type InsnMap struct {
	Funcs [][]Mapping

	fun  int
	base int32
	ins  int32
}

func (im *InsnMap) Init(numFuncs int) {
	im.Funcs = make([][]Mapping, numFuncs)
	im.fun = -1
}

func (im *InsnMap) PutFunc(pos int32) {
	im.fun++
	im.base = pos
	im.ins = -1
}

func (im *InsnMap) PutInsn(absPos int32) {
	im.ins++
	relPos := absPos - im.base

	prev := len(im.Funcs[im.fun]) - 1
	if prev >= 0 && im.Funcs[im.fun][prev].ObjectOffset == relPos {
		// Replace previous mapping because no machine code was generated
		im.Funcs[im.fun][prev].SourceIndex = im.ins
	} else {
		im.Funcs[im.fun] = append(im.Funcs[im.fun], Mapping{relPos, im.ins})
	}
}
