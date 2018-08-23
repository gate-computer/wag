// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"github.com/tsavola/wag/internal/module"
)

type TextBuffer = module.TextBuffer
type DataBuffer = module.DataBuffer

// defaultBuffer is a variable-capacity implementation of TextBuffer and
// DataBuffer.
type defaultBuffer struct {
	b []byte
}

func (d *defaultBuffer) Bytes() []byte     { return d.b }
func (d *defaultBuffer) Pos() int32        { return int32(len(d.b)) }
func (d *defaultBuffer) PutByte(b byte)    { d.Extend(1)[0] = b }
func (d *defaultBuffer) PutBytes(b []byte) { copy(d.Extend(len(b)), b) }

func (d *defaultBuffer) Extend(n int) []byte {
	offset := len(d.b)
	if size := offset + n; size <= cap(d.b) {
		d.b = d.b[:size]
	} else {
		b := make([]byte, size)
		copy(b, d.b)
		d.b = b
	}
	return d.b[offset:]
}

func (d *defaultBuffer) ResizeBytes(n int) []byte {
	if n <= cap(d.b) {
		d.b = d.b[:n]
	} else {
		b := make([]byte, n)
		copy(b, d.b)
		d.b = b
	}
	return d.b
}
