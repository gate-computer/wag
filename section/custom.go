// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"io"
	"io/ioutil"

	"gate.computer/wag/binary"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/section"
)

// Unwrapped may be returned by custom section content loaders.
var Unwrapped error = section.Unwrapped

// Reader is suitable for reading sections.
type Reader = binary.Reader

// Loader is suitable for use with section loading functions.
type Loader = loader.Loader

// NewLoader creates a WebAssembly section loader.
func NewLoader(r Reader) Loader {
	return loader.New(r, 0)
}

type CustomContentLoader func(sectionName string, r Reader, payloadSize uint32) error

type customLoaderMux struct {
	loaders map[string]CustomContentLoader
}

func CustomLoader(loaders map[string]CustomContentLoader) func(Reader, uint32) error {
	mux := customLoaderMux{loaders: loaders}
	return mux.load
}

func (mux customLoaderMux) load(r Reader, length uint32) error {
	nameLen, n, err := binary.Varuint32(r)
	if err != nil {
		return err
	}
	length -= uint32(n)

	nameData := make([]byte, nameLen)
	if _, err := io.ReadFull(r, nameData); err != nil {
		return err
	}
	name := loader.String(nameData, "custom section name")
	length -= nameLen

	if f := mux.loaders[name]; f != nil {
		return f(name, r, length)
	}

	_, err = io.CopyN(ioutil.Discard, r, int64(length))
	return err
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
