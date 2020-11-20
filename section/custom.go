// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"io"
	"io/ioutil"

	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/reader"
)

type Reader = reader.R

type CustomContentLoader func(sectionName string, r Reader, payloadLen uint32) error

type customLoaderMux struct {
	loaders   map[string]CustomContentLoader
	maxKeyLen uint32
}

func CustomLoader(loaders map[string]CustomContentLoader) func(Reader, uint32) error {
	mux := customLoaderMux{loaders: loaders}
	for k := range loaders {
		if n := len(k); n > int(mux.maxKeyLen) {
			mux.maxKeyLen = uint32(n)
		}
	}
	return mux.load
}

func (mux customLoaderMux) load(r Reader, length uint32) (err error) {
	nameLen, n, err := loader.Varuint32(r)
	if err != nil {
		return
	}
	length -= uint32(n)

	if nameLen <= mux.maxKeyLen {
		name := string(loader.L{R: r}.Bytes(nameLen))
		length -= nameLen

		if f := mux.loaders[name]; f != nil {
			err = f(name, r, length)
			return
		}
	}

	_, err = io.CopyN(ioutil.Discard, r, int64(length))
	return
}

type CustomMapping ByteRange

// Loader of arbitrary custom section.  Remembers position, discards content.
func (target *CustomMapping) Loader(sectionMap *Map) CustomContentLoader {
	return func(_ string, r reader.R, length uint32) (err error) {
		*target = CustomMapping(sectionMap.Sections[Custom]) // The latest one.
		_, err = io.CopyN(ioutil.Discard, r, int64(length))
		return
	}
}

type CustomSections struct {
	Sections map[string][]byte
}

func (cs *CustomSections) Load(name string, r reader.R, length uint32) (err error) {
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
