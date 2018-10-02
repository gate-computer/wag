// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"github.com/tsavola/wag/internal/obj"
)

type ObjectMapper = obj.ObjectMapper

type dummyMap struct{}

func (dummyMap) InitObjectMap(int, int)   {}
func (dummyMap) PutImportFuncAddr(int32)  {}
func (dummyMap) PutFuncAddr(int32)        {}
func (dummyMap) PutCallSite(int32, int32) {}
func (dummyMap) PutInsnAddr(int32)        {}
func (dummyMap) PutDataBlock(int32, int)  {}

// FuncMap implements ObjectMapper.  It stores addresses of the non-import
// functions which were specified by the creator.
type FuncMap struct {
	FuncAddrs map[uint32]int32

	funcIndex uint32
}

func NewFuncMap(funcIndexes ...uint32) (m *FuncMap) {
	m = &FuncMap{
		FuncAddrs: make(map[uint32]int32),
	}
	for _, index := range funcIndexes {
		m.FuncAddrs[index] = 0
	}
	return
}

func (*FuncMap) InitObjectMap(int, int) {}

func (m *FuncMap) PutImportFuncAddr(int32) {
	m.funcIndex++
}

func (m *FuncMap) PutFuncAddr(addr int32) {
	if _, specified := m.FuncAddrs[m.funcIndex]; specified {
		m.FuncAddrs[m.funcIndex] = addr
	}
	m.funcIndex++
}

func (*FuncMap) PutCallSite(int32, int32) {}
func (*FuncMap) PutInsnAddr(int32)        {}
func (*FuncMap) PutDataBlock(int32, int)  {}
