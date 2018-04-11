// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sections

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
)

const (
	maxSectionNameLen = 255 // TODO
)

type UnknownLoader func(string, module.Reader) error

type UnknownLoaders map[string]UnknownLoader

func (uls UnknownLoaders) Load(r module.Reader, payloadLen uint32) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	// io.LimitedReader doesn't implement module.Reader, so do this instead
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		panic(err)
	}
	load := loader.L{Reader: bytes.NewReader(payload)}

	nameLen := load.Varuint32()
	if nameLen > maxSectionNameLen {
		panic(errors.New("unknown section name is too long"))
	}

	name := string(load.Bytes(nameLen))

	if f := uls[name]; f != nil {
		if err := f(name, load.Reader); err != nil { // avoid nested loaders
			panic(err)
		}
	} else {
		if _, err := io.Copy(ioutil.Discard, load.Reader); err != nil {
			panic(err)
		}
	}

	return
}
