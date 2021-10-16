// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"io"
	"io/ioutil"

	"gate.computer/wag/binary"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
)

func Find(
	findID module.SectionID,
	load *loader.L,
	sectionMapper func(sectionID byte, r binary.Reader) (payloadLen uint32, err error),
	customLoader func(binary.Reader, uint32) error,
) module.SectionID {
	for {
		sectionID, err := load.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0
			}
			panic(err)
		}

		id := module.SectionID(sectionID)

		switch {
		case id == module.SectionCustom:
			var payloadLen uint32

			if sectionMapper != nil {
				payloadLen, err = sectionMapper(sectionID, load)
				if err != nil {
					panic(err)
				}
			} else {
				payloadLen = load.Varuint32()
			}

			if customLoader != nil {
				err = customLoader(load, payloadLen)
			} else {
				_, err = io.CopyN(ioutil.Discard, load, int64(payloadLen))
			}
			if err != nil {
				panic(err)
			}

		case id == findID:
			return id

		default:
			load.UnreadByte()
			return id
		}
	}
}
