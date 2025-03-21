// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"errors"
	"io"
	"math"

	"gate.computer/wag/binary"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/pan"
)

var Unwrapped = errors.New("section unwrapped") //lint:ignore ST1012 special

// ModuleMapper gathers information about positions of WebAssembly sections.
type ModuleMapper interface {
	// PutSection is invoked just after the payload length has been read.
	// Section offset is the position of the section id.  Section size covers
	// section id byte, encoded payload length, and payload content.
	PutSection(sectionID byte, sectionOffset int64, sectionSize, payloadSize uint32) error
}

func Find(
	findID module.SectionID,
	load *loader.L,
	mapper ModuleMapper,
	customLoader func(binary.Reader, uint32) error,
) (int64, module.SectionID) {
	for {
		sectionOffset := load.Tell()

		sectionID, err := load.ReadByte()
		if err == io.EOF {
			return sectionOffset, 0
		}
		pan.Check(err)

		id := module.SectionID(sectionID)

		switch {
		case id == module.SectionCustom:
			payloadSize := LoadPayloadSize(sectionOffset, id, load, mapper)
			payloadOffset := load.Tell()
			partial := false

			if customLoader != nil {
				err := customLoader(load, payloadSize)
				if err == Unwrapped {
					partial = true
				}
				pan.Check(err)
			} else {
				pan.Must(io.CopyN(io.Discard, load, int64(payloadSize)))
			}

			CheckConsumption(load, payloadOffset, payloadSize, partial)

		case id == findID:
			return sectionOffset, id

		default:
			load.UnreadByte()
			return sectionOffset, id
		}
	}
}

func LoadPayloadSize(
	sectionOffset int64,
	id module.SectionID,
	load *loader.L,
	mapper ModuleMapper,
) uint32 {
	payloadSize := load.Varuint32()
	sectionSize := load.Tell() - sectionOffset + int64(payloadSize)
	if sectionSize > math.MaxInt32 {
		pan.Panic(module.Error("section end offset out of bounds"))
	}

	if mapper != nil {
		pan.Check(mapper.PutSection(byte(id), sectionOffset, uint32(sectionSize), payloadSize))
	}

	return payloadSize
}

func CheckConsumption(load *loader.L, payloadOffset int64, payloadSize uint32, partial bool) {
	consumed := load.Tell() - payloadOffset
	if consumed == int64(payloadSize) {
		return
	}
	if partial && consumed < int64(payloadSize) {
		return
	}
	pan.Panic(module.Errorf("section size is %d but %d bytes was read", payloadSize, consumed))
}
