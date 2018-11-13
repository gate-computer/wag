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
	PutImportFuncAddr(addr int32)
	PutFuncAddr(addr int32)
	PutCallSite(returnAddr int32, stackOffset int32)
	PutInsnAddr(addr int32)
	PutDataBlock(addr int32, length int)
}
