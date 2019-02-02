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
	FuncAddrs []uint32
}

func (m *FuncMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	m.FuncAddrs = make([]uint32, 0, numImportFuncs+numOtherFuncs)
}

func (m *FuncMap) PutImportFuncAddr(addr uint32) {
	m.PutFuncAddr(addr)
}

func (m *FuncMap) PutFuncAddr(addr uint32) {
	m.FuncAddrs = append(m.FuncAddrs, addr)
}

func (*FuncMap) PutCallSite(uint32, int32)  {}
func (*FuncMap) PutInsnAddr(uint32)         {}
func (*FuncMap) PutDataBlock(uint32, int32) {}

func (m *FuncMap) FindAddr(retAddr uint32) (funcIndex, _, _ uint32, _ int32, initial, ok bool) {
	if len(m.FuncAddrs) == 0 {
		return
	}

	firstFuncAddr := m.FuncAddrs[0]
	if retAddr > 0 && retAddr < firstFuncAddr {
		initial = true
		ok = true
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

		return retAddr <= funcEndAddr
	})
	if i < len(m.FuncAddrs) {
		funcIndex = uint32(i)
		ok = true
	}
	return
}
