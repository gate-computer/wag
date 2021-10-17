// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"errors"
	"io"
	"io/ioutil"
	"math"

	"gate.computer/wag/binary"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
)

var Unwrapped = errors.New("section unwrapped")

func Find(
	findID module.SectionID,
	load *loader.L,
	sectionMapper func(sectionID byte, sectionOffset int64, sectionSize, payloadSize uint32) error,
	customLoader func(binary.Reader, uint32) error,
) (int64, module.SectionID) {
	for {
		sectionOffset := load.Tell()

		sectionID, err := load.ReadByte()
		if err != nil {
			if err == io.EOF {
				return sectionOffset, 0
			}
			panic(err)
		}

		id := module.SectionID(sectionID)

		switch {
		case id == module.SectionCustom:
			payloadSize := LoadPayloadSize(sectionOffset, id, load, sectionMapper)
			payloadOffset := load.Tell()
			partial := false

			if customLoader != nil {
				if err := customLoader(load, payloadSize); err != nil {
					if err == Unwrapped {
						partial = true
					} else {
						panic(err)
					}
				}
			} else {
				if _, err := io.CopyN(ioutil.Discard, load, int64(payloadSize)); err != nil {
					panic(err)
				}
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
	sectionMapper func(sectionID byte, sectionOffset int64, sectionSize, payloadSize uint32) error,
) uint32 {
	payloadSize := load.Varuint32()
	sectionSize := load.Tell() - sectionOffset + int64(payloadSize)
	if sectionSize > math.MaxInt32 {
		panic(module.Error("section end offset out of bounds"))
	}

	if sectionMapper != nil {
		if err := sectionMapper(byte(id), sectionOffset, uint32(sectionSize), payloadSize); err != nil {
			panic(err)
		}
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
	panic(module.Errorf("section size is %d but %d bytes was read", payloadSize, consumed))
}
