// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"gate.computer/wag/internal/module"
)

const (
	moduleHeaderSize = 8
)

type ByteRange struct {
	Offset int64
	Length int64
}

// Map of section positions within the WebAssebly binary module.  Map must me
// initialied with MakeMap or NewMap.
//
// Section offset is always nonzero for standard sections; if the section is
// missing, it's the position where it would be.  Section length is nonzero if
// the section is present.
//
// Sections[Custom] holds information about the last (or latest) custom
// section.  Its offset is zero if there are no custom sections.
type Map struct {
	Sections [module.NumSections]ByteRange
}

// MakeMap which represents an empty module.
func MakeMap() (m Map) {
	for i := 1; i < int(module.NumSections); i++ {
		m.Sections[i].Offset = moduleHeaderSize
	}
	return
}

// NewMap which represents an empty module.
func NewMap() *Map {
	m := MakeMap()
	return &m
}

// MapSection method is a section mapper function.
func (m *Map) MapSection(sectionID byte, sectionOffset int64, sectionSize, payloadSize uint32) error {
	m.Sections[sectionID] = ByteRange{sectionOffset, int64(sectionSize)}

	if ID(sectionID) != Custom {
		// Default positions of remaining standard sections.
		for i := int(sectionID) + 1; i < int(module.NumSections); i++ {
			m.Sections[i].Offset = sectionOffset
		}
	}

	return nil
}
