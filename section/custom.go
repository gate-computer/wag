// Copyright (c) 2016 Timo Savola. All rights reserved.
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

const (
	maxSectionNameLen = 255 // TODO
)

type Reader = reader.R

type CustomLoaders map[string]func(sectionName string, r Reader, payloadLen uint32) error

func (uls CustomLoaders) Load(r Reader, payloadLen uint32) (err error) {
	load := loader.L{R: r}

	nameLen := load.Varuint32()
	if nameLen > maxSectionNameLen {
		err = module.Error("custom section name is too long")
		return
	}

	name := string(load.Bytes(nameLen))

	if f := uls[name]; f != nil {
		err = f(name, load.R, payloadLen)
	} else {
		_, err = io.CopyN(ioutil.Discard, load.R, int64(payloadLen))
	}
	return
}

type CustomMapping ByteRange

// Loader of arbitrary custom section.  Remembers position, discards content.
func (target *CustomMapping) Loader(sectionMap *Map) func(string, reader.R, uint32) error {
	return func(_ string, r reader.R, payloadLen uint32) (err error) {
		*target = CustomMapping(sectionMap.Sections[Custom]) // The latest one.
		_, err = io.CopyN(ioutil.Discard, r, int64(payloadLen))
		return
	}
}

type CustomSections struct {
	Sections map[string][]byte
}

func (cs *CustomSections) Load(name string, r reader.R, payloadLen uint32) (err error) {
	data := make([]byte, payloadLen)

	_, err = io.ReadFull(r, data)
	if err != nil {
		return
	}

	if cs.Sections == nil {
		cs.Sections = make(map[string][]byte)
	}

	cs.Sections[name] = data
	return
}
