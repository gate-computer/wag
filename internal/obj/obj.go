// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package obj

const (
	Word = 8 // stack entry size
)

// ObjectMapper gathers information about positions of (WebAssembly) functions,
// function calls and instructions within the text (machine code) section.
type ObjectMapper interface {
	InitObjectMap(numImportFuncs, numOtherFuncs int)
	PutImportFuncAddr(addr uint32)
	PutFuncAddr(addr uint32)
	PutCallSite(returnAddr uint32, stackOffset int32)
	PutInsnAddr(addr uint32)
	PutDataBlock(addr uint32, length int32)
}
