// Copyright (c) 2022 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"sort"

	"gate.computer/wag/wa"
)

type funcType struct {
	t        wa.FuncType
	index    uint32
	newIndex uint32
}

// funcTypeOrder groups identical types together, smallest index first.
type funcTypeOrder []funcType

func (a funcTypeOrder) Len() int      { return len(a) }
func (a funcTypeOrder) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func (a funcTypeOrder) Less(i, j int) bool {
	if n := a[i].t.Compare(a[j].t); n != 0 {
		return n < 0
	}
	return a[i].index < a[j].index
}

func initTableTypes(m *Module) {
	// All function types.
	types := make([]funcType, 0, len(m.m.Types))

	for typeIndex, t := range m.m.Types {
		types = append(types, funcType{
			t:        t,
			index:    uint32(typeIndex),
			newIndex: uint32(typeIndex),
		})
	}

	sort.Sort(funcTypeOrder(types))

	// Number of elements which need type index remapping.
	var count int

	if len(types) > 0 {
		canonical := types[0].index

		for i := 1; i < len(types); i++ {
			prev := &types[i-1]
			curr := &types[i]

			if !prev.t.Equal(curr.t) {
				canonical = curr.index
			} else {
				curr.newIndex = canonical
				count++
			}
		}
	}

	if count == 0 {
		return
	}

	// Type indexes mapped to canonical type indexes.
	m.m.CanonicalTypes = make(map[uint32]uint32, count)

	for _, curr := range types {
		if curr.newIndex != curr.index {
			m.m.CanonicalTypes[curr.index] = curr.newIndex
		}
	}
}
