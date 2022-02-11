// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package obj

const (
	Word = 8 // stack entry size
)

// ObjectMapper gathers information about positions of (WebAssembly) functions,
// function calls and traps within the text (machine code) section.
type ObjectMapper interface {
	InitObjectMap(numImportFuncs, numOtherFuncs int)
	PutFuncAddr(addr uint32)
	PutCallSite(returnAddr uint32, stackOffset int32)
}

// DebugObjectMapper gathers information about positions of all (WebAssembly)
// instructions within the text (machine code) section.
type DebugObjectMapper interface {
	ObjectMapper
	PutInsnAddr(addr, sourceAddr uint32)
	PutDataBlock(addr uint32, length int32)
}

type DummyMapper struct{}

func (DummyMapper) InitObjectMap(int, int)    {}
func (DummyMapper) PutFuncAddr(uint32)        {}
func (DummyMapper) PutCallSite(uint32, int32) {}

type DummyDebugMapper struct{ DummyMapper }

func (DummyDebugMapper) PutInsnAddr(uint32)         {}
func (DummyDebugMapper) PutDataBlock(uint32, int32) {}
