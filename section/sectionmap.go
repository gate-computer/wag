// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"github.com/tsavola/wag/internal/module"
)

const (
	moduleHeaderSize = 8
	sectionIdSize    = 1
)

type ByteRange struct {
	Offset int64
	Length int64
}

// Map of section offset and sizes within the WebAssebly binary module.  Offset
// and Length are nonzero if a section is present.  ModuleSections[Custom]
// holds information about the last (or latest) custom section.
type Map struct {
	Sections [module.NumSections]ByteRange
}

func (m *Map) Mapper() func(byte, uint32) {
	offset := int64(moduleHeaderSize)

	return func(sectionId byte, payloadLen uint32) {
		payloadLenSize := 1
		for x := payloadLen; x >= 0x80; {
			x >>= 7
			payloadLenSize++
		}

		length := sectionIdSize + int64(payloadLenSize) + int64(payloadLen)
		m.Sections[sectionId] = ByteRange{offset, length}
		offset += length
	}
}
