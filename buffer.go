// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"errors"
)

var errOutOfCapacity = errors.New("buffer ran out of capacity")

// FixedBuffer is a fixed-capacity implementation of DataBuffer.
type FixedBuffer struct {
	b []byte
}

func NewFixedBuffer(b []byte) *FixedBuffer { return &FixedBuffer{b} }
func (f *FixedBuffer) Bytes() []byte       { return f.b }

func (f *FixedBuffer) ResizeBytes(n int) []byte {
	if n <= cap(f.b) {
		f.b = f.b[:n]
	} else {
		panic(errOutOfCapacity)
	}
	return f.b
}

// defaultDataBuffer is a variable-capacity implementation of DataBuffer.
type defaultDataBuffer struct {
	b []byte
}

func (d *defaultDataBuffer) Bytes() []byte { return d.b }

func (d *defaultDataBuffer) ResizeBytes(n int) []byte {
	if n <= cap(d.b) {
		d.b = d.b[:n]
	} else {
		b := make([]byte, n)
		copy(b, d.b)
		d.b = b
	}
	return d.b
}
