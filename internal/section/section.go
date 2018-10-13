// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"io"
	"io/ioutil"

	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/reader"
)

func Find(
	findId module.SectionId,
	load loader.L,
	sectionMapper func(sectionId byte, payloadLen uint32),
	unknownLoader func(reader.R, uint32) error,
) module.SectionId {
	for {
		sectionId, err := load.R.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0
			}
			panic(err)
		}

		id := module.SectionId(sectionId)

		switch {
		case id == module.SectionUnknown:
			payloadLen := load.Varuint32()

			if sectionMapper != nil {
				sectionMapper(sectionId, payloadLen)
			}

			if unknownLoader != nil {
				err = unknownLoader(load.R, payloadLen)
			} else {
				_, err = io.CopyN(ioutil.Discard, load.R, int64(payloadLen))
			}
			if err != nil {
				panic(err)
			}

		case id == findId:
			return id

		default:
			load.R.UnreadByte()
			return id
		}
	}
}
