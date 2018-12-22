// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"github.com/tsavola/wag/internal/loader"
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

// Map of section positions within the WebAssebly binary module.  Offset and
// Length are nonzero if a section is present.  Sections[Custom] holds
// information about the last (or latest) custom section.
type Map struct {
	Sections [module.NumSections]ByteRange
}

func (m *Map) Mapper() func(byte, Reader) (uint32, error) {
	offset := int64(moduleHeaderSize)

	return func(sectionId byte, r Reader) (payloadLen uint32, err error) {
		payloadLen, payloadLenSize, err := loader.Varuint32(r)
		if err != nil {
			return
		}

		length := sectionIdSize + int64(payloadLenSize) + int64(payloadLen)
		m.Sections[sectionId] = ByteRange{offset, length}
		offset += length
		return
	}
}
