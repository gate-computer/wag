// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object

import (
	"math"
	"sort"
)

// FuncMap implements compile.ObjectMapper.  It stores all function addresses,
// but no call or instruction information.
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
func (*FuncMap) PutDataBlock(int32, int)  {}

func (m *FuncMap) FindAddr(retAddr int32) (funcIndex, _, _ int32, initial, ok bool) {
	if len(m.FuncAddrs) == 0 {
		return
	}

	firstFuncAddr := m.FuncAddrs[0]
	if retAddr > 0 && retAddr < int32(firstFuncAddr) {
		initial = true
		ok = true
		return
	}

	i := sort.Search(len(m.FuncAddrs), func(i int) bool {
		var funcEndAddr int32

		i++
		if i == len(m.FuncAddrs) {
			funcEndAddr = math.MaxInt32
		} else {
			funcEndAddr = int32(m.FuncAddrs[i])
		}

		return retAddr <= funcEndAddr
	})
	if i < len(m.FuncAddrs) {
		funcIndex = int32(i)
		ok = true
	}
	return
}
