// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object

import (
	"math"
	"sort"
)

// FuncMap implements compile.ObjectMapper.  It stores function addresses, but
// no call, trap or instruction information.
//
// FuncAddrs may be preallocated by initializing the field with a non-nil,
// empty array.
type FuncMap struct {
	FuncAddrs []uint32
}

func (m *FuncMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	if len(m.FuncAddrs) > 0 {
		panic("FuncAddrs is not empty")
	}

	if num := numImportFuncs + numOtherFuncs; cap(m.FuncAddrs) < num {
		m.FuncAddrs = make([]uint32, 0, num)
	}
}

func (m *FuncMap) PutFuncAddr(addr uint32) {
	m.FuncAddrs = append(m.FuncAddrs, addr)
}

func (*FuncMap) PutCallSite(uint32, int32) {}

func (m *FuncMap) FindFunc(addr uint32) (index int, found bool) {
	index = -1

	i := sort.Search(len(m.FuncAddrs), func(i int) bool {
		return m.FuncAddrs[i] >= addr
	})
	if i < len(m.FuncAddrs) && m.FuncAddrs[i] == addr {
		index = i
		found = true
	}
	return
}

func (m *FuncMap) FindCall(retAddr uint32,
) (init bool, funcIndex, callIndex int, stackOffset int32, retOffset uint32) {
	funcIndex = -1
	callIndex = -1

	if len(m.FuncAddrs) == 0 {
		return
	}

	firstFuncAddr := m.FuncAddrs[0]
	if retAddr > 0 && retAddr < firstFuncAddr {
		init = true
		return
	}

	i := sort.Search(len(m.FuncAddrs), func(i int) bool {
		var funcEndAddr uint32

		i++
		if i == len(m.FuncAddrs) {
			funcEndAddr = math.MaxUint32
		} else {
			funcEndAddr = m.FuncAddrs[i]
		}

		return retAddr < funcEndAddr
	})
	if i < len(m.FuncAddrs) {
		funcIndex = i
	}
	return
}
