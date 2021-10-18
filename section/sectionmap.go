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

// ByteRange expresses a location and a length within a byte stream.  The
// length is at most MaxUint32, and the inclusive start and exclusive end
// offsets are in range [0,MaxInt64].
type ByteRange struct {
	Start int64
	Size  uint32
}

// End of the range (exclusive).
func (r ByteRange) End() int64 {
	return r.Start + int64(r.Size)
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
		m.Sections[i].Start = moduleHeaderSize
	}
	return
}

// NewMap which represents an empty module.
func NewMap() *Map {
	m := MakeMap()
	return &m
}

// PutSection location on the map.
func (m *Map) PutSection(sectionID byte, sectionOffset int64, sectionSize, payloadSize uint32) error {
	m.Sections[sectionID] = ByteRange{sectionOffset, sectionSize}

	if ID(sectionID) != Custom {
		// Default positions of remaining standard sections.
		for i := int(sectionID) + 1; i < int(module.NumSections); i++ {
			m.Sections[i].Start = sectionOffset
		}
	}

	return nil
}
