// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"gate.computer/wag/object"
)

// TrapMap implements compile.DebugObjectMapper.  It stores function addresses,
// and all call and trap sites.  Instruction information is not stored.
type TrapMap struct {
	object.CallMap                   // Function calls and recoverable (portable) traps.
	TrapSites      []object.CallSite // Unrecoverable (or nonportable) traps.
}

func (m *TrapMap) PutTrapSite(retAddr uint32, stackOffset int32) {
	m.TrapSites = append(m.TrapSites, object.CallSite{
		RetAddr:     retAddr,
		StackOffset: stackOffset,
	})
}

func (TrapMap) PutInsnAddr(uint32)         {}
func (TrapMap) PutDataBlock(uint32, int32) {}

func (m *TrapMap) FindCall(retAddr uint32,
) (init bool, funcIndex, callIndex int, stackOffset int32, retOffset uint32) {
	init, funcIndex, callIndex, stackOffset, retOffset = m.CallMap.FindCall(retAddr)

	if callIndex < 0 {
		if i, found := object.FindCallSite(m.TrapSites, retAddr); found {
			stackOffset = m.TrapSites[i].StackOffset
		}
	}
	return
}
