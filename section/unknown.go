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

type UnknownLoader func(sectionName string, section Reader) error

type UnknownLoaders map[string]UnknownLoader

func (uls UnknownLoaders) Load(r Reader, payloadLen uint32) (err error) {
	// io.LimitedReader doesn't implement Reader, so do this instead
	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return
	}

	load := loader.L{R: bytes.NewReader(payload)}

	nameLen := load.Varuint32()
	if nameLen > maxSectionNameLen {
		err = errors.New("unknown section name is too long")
		return
	}

	name := string(load.Bytes(nameLen))

	if f := uls[name]; f != nil {
		err = f(name, load.R)
	} else {
		_, err = io.Copy(ioutil.Discard, load.R)
	}
	return
}
