// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object

import (
	"sort"
)

// CallSite represents a position within the text section (machine code) where
// a function call is made.
//
// The struct size or layout will not change between minor versions.
type CallSite struct {
	RetAddr     uint32 // The address immediately after the call instruction
	StackOffset int32  // Calling function's stack usage at time of call
}

// CallMap implements compile.ObjectMapper.  It stores all function addresses
// and call sites, but no instruction information.
type CallMap struct {
	FuncMap
	CallSites []CallSite
}

func (m *CallMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	m.FuncMap.InitObjectMap(numImportFuncs, numOtherFuncs)
	m.CallSites = make([]CallSite, 0, numImportFuncs+numOtherFuncs) // conservative guess
}

func (m *CallMap) PutCallSite(retAddr uint32, stackOffset int32) {
	m.CallSites = append(m.CallSites, CallSite{retAddr, stackOffset})
}

func (m CallMap) FindAddr(retAddr uint32) (funcIndex, callIndex, _ uint32, stackOffset int32, initial, ok bool) {
	funcIndex, _, _, _, initial, funcOk := m.FuncMap.FindAddr(retAddr)
	if !funcOk {
		return
	}

	i := sort.Search(len(m.CallSites), func(i int) bool {
		return m.CallSites[i].RetAddr >= retAddr
	})
	if i < len(m.CallSites) && m.CallSites[i].RetAddr == retAddr {
		callIndex = uint32(i)
		stackOffset = m.CallSites[i].StackOffset
		ok = true
	}
	return
}
