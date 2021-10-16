// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"io"
	"io/ioutil"

	"gate.computer/wag/binary"
	"gate.computer/wag/internal/loader"
)

type Reader = binary.Reader

type CustomContentLoader func(sectionName string, r Reader, payloadLen uint32) error

type customLoaderMux struct {
	loaders map[string]CustomContentLoader
}

func CustomLoader(loaders map[string]CustomContentLoader) func(Reader, uint32) error {
	mux := customLoaderMux{loaders: loaders}
	return mux.load
}

func (mux customLoaderMux) load(r Reader, length uint32) (err error) {
	nameLen, n, err := binary.Varuint32(r)
	if err != nil {
		return
	}
	length -= uint32(n)

	name := loader.New(r).String(nameLen, "custom section name")
	length -= nameLen

	if f := mux.loaders[name]; f != nil {
		err = f(name, r, length)
		return
	}

	_, err = io.CopyN(ioutil.Discard, r, int64(length))
	return
}

type CustomMapping ByteRange

// Loader of arbitrary custom section.  Remembers position, discards content.
func (target *CustomMapping) Loader(sectionMap *Map) CustomContentLoader {
	return func(_ string, r Reader, length uint32) (err error) {
		*target = CustomMapping(sectionMap.Sections[Custom]) // The latest one.
		_, err = io.CopyN(ioutil.Discard, r, int64(length))
		return
	}
}

type CustomSections struct {
	Sections map[string][]byte
}

func (cs *CustomSections) Load(name string, r Reader, length uint32) (err error) {
	data := make([]byte, length)

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
