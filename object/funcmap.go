// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object

// FuncMap implements compile.ObjectMap.  It stores all function addresses, but
// no call or instruction information.
type FuncMap struct {
	FuncAddrs []int32
}

func (m *FuncMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	m.FuncAddrs = make([]int32, 0, numImportFuncs+numOtherFuncs)
}

func (m *FuncMap) PutImportFuncAddr(addr int32) {
	m.PutFuncAddr(addr)
}

func (m *FuncMap) PutFuncAddr(addr int32) {
	m.FuncAddrs = append(m.FuncAddrs, addr)
}

func (*FuncMap) PutCallSite(int32, int32) {}
func (*FuncMap) PutInsnAddr(int32)        {}
