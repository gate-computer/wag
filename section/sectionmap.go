// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"gate.computer/wag/internal/module"
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

// PutSection location on the map.
func (m *Map) PutSection(sectionID byte, sectionOffset int64, sectionSize, payloadSize uint32) error {
	m.Sections[sectionID] = ByteRange{sectionOffset, sectionSize}

	// Initialize other sections' offsets during the first invocation.  The
	// assumption is that a valid WebAssembly module contains at least one
	// standard section, so PutSection will be invoked at least once; the empty
	// module might as well have its non-existent sections at offset 0.
	if ID(sectionID) != Custom {
		// Imaginary positions of missing standard sections.
		for i := int(sectionID) - 1; i > 0 && m.Sections[i].Start == 0; i-- {
			m.Sections[i].Start = sectionOffset
		}

		// Default positions of remaining standard sections.
		for i := int(sectionID) + 1; i < int(module.NumSections); i++ {
			m.Sections[i].Start = sectionOffset
		}
	}

	return nil
}
