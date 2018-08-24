// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/reader"
)

const (
	maxSectionNameLen = 255 // TODO
)

type UnknownLoader func(string, reader.R) error

type UnknownLoaders map[string]UnknownLoader

func (uls UnknownLoaders) Load(r reader.R, payloadLen uint32) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	// io.LimitedReader doesn't implement reader.R, so do this instead
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		panic(err)
	}
	load := loader.L{R: bytes.NewReader(payload)}

	nameLen := load.Varuint32()
	if nameLen > maxSectionNameLen {
		panic(errors.New("unknown section name is too long"))
	}

	name := string(load.Bytes(nameLen))

	if f := uls[name]; f != nil {
		if err := f(name, load.R); err != nil { // avoid nested loaders
			panic(err)
		}
	} else {
		if _, err := io.Copy(ioutil.Discard, load.R); err != nil {
			panic(err)
		}
	}

	return
}
