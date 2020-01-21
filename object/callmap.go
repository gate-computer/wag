// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object

import (
	"sort"
)

// CallSite represents an offset within the text section (machine code) where a
// function call is made.
//
// The struct size or layout will not change between minor versions.
type CallSite struct {
	RetAddr     uint32 // The address immediately after the call instruction
	StackOffset int32  // Calling function's stack usage at time of call
}

func FindCallSite(a []CallSite, retAddr uint32) (i int, found bool) {
	i = sort.Search(len(a), func(i int) bool {
		return a[i].RetAddr >= retAddr
	})
	found = i < len(a) && a[i].RetAddr == retAddr
	return
}

// CallMap implements compile.ObjectMapper.  It stores function addresses, and
// sites of function calls and suspension points.  Other trap and instruction
// information is not stored.
//
// Initial CallSites capacity may be allocated by initializing the field with a
// non-nil, empty array.
type CallMap struct {
	FuncMap
	CallSites []CallSite
}

func (m *CallMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	if len(m.CallSites) > 0 {
		panic("CallSites is not empty")
	}

	m.FuncMap.InitObjectMap(numImportFuncs, numOtherFuncs)

	if m.CallSites == nil {
		// Conservative guess (assuming there are no unused functions).
		m.CallSites = make([]CallSite, 0, numImportFuncs+numOtherFuncs)
	}
}

func (m *CallMap) PutCallSite(retAddr uint32, stackOffset int32) {
	m.CallSites = append(m.CallSites, CallSite{retAddr, stackOffset})
}

func (m *CallMap) FindCall(retAddr uint32,
) (init bool, funcIndex, callIndex int, stackOffset int32, retOffset uint32) {
	init, funcIndex, callIndex, stackOffset, retOffset = m.FuncMap.FindCall(retAddr)

	if i, found := FindCallSite(m.CallSites, retAddr); found {
		callIndex = i
		stackOffset = m.CallSites[i].StackOffset
	}
	return
}
