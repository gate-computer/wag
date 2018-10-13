// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/reader"
)

const (
	maxSectionNameLen = 255 // TODO
)

type Reader = reader.R

type CustomLoaders map[string]func(sectionName string, section Reader) error

func (uls CustomLoaders) Load(r Reader, payloadLen uint32) (err error) {
	// io.LimitedReader doesn't implement Reader, so do this instead
	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return
	}

	payloadReader := bytes.NewReader(payload)
	load := loader.L{R: payloadReader}

	nameLen := load.Varuint32()
	if nameLen > maxSectionNameLen {
		err = errors.New("custom section name is too long")
		return
	}

	name := string(load.Bytes(nameLen))

	if f := uls[name]; f != nil {
		err = f(name, payloadReader)
	} else {
		// It's a bytes.Reader, no need to discard.
	}
	return
}

type CustomMapping ByteRange

// Loader of any custom section.  Stores its offset and size within the
// WebAssembly binary module, and discards content.
func (target *CustomMapping) Loader(sectionMap *Map) func(string, reader.R) error {
	return func(_ string, r reader.R) (err error) {
		*target = CustomMapping(sectionMap.Sections[Custom]) // The latest one.

		if _, ok := r.(*bytes.Reader); ok {
			// No need to discard.
		} else {
			_, err = io.Copy(ioutil.Discard, r)
		}
		return
	}
}
