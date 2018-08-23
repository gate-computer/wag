// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object

// TextAddr represents a non-negative offset from the start of the text section
// (machine code).
type TextAddr int32

// CallSite represents a position within the text section (machine code) where
// a function call is made.
type CallSite struct {
	ReturnAddr  TextAddr // The address immediately after the call instruction
	StackOffset int32    // Calling function's stack usage at time of call
}

// FuncMap implements compile.ObjectMap.  It stores all function addresses, but
// no call or instruction information.
type FuncMap struct {
	FuncAddrs []TextAddr
}

func (m *FuncMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	m.FuncAddrs = make([]TextAddr, 0, numImportFuncs+numOtherFuncs)
}

func (m *FuncMap) PutImportFuncAddr(addr TextAddr) {
	m.PutFuncAddr(addr)
}

func (m *FuncMap) PutFuncAddr(addr TextAddr) {
	m.FuncAddrs = append(m.FuncAddrs, addr)
}

func (*FuncMap) PutCallSite(TextAddr, int32) {}
func (*FuncMap) PutInsnAddr(TextAddr)        {}

// CallMap implements compile.ObjectMap.  It stores all function addresses and
// call sites, but no instruction information.
type CallMap struct {
	FuncMap
	CallSites []CallSite
}

func (m *CallMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	m.FuncMap.InitObjectMap(numImportFuncs, numOtherFuncs)
	m.CallSites = make([]CallSite, 0, numImportFuncs+numOtherFuncs) // conservative guess
}

func (m *CallMap) PutCallSite(retAddr TextAddr, stackOffset int32) {
	m.CallSites = append(m.CallSites, CallSite{retAddr, stackOffset})
}
