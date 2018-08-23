// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffer

import (
	"errors"
)

var errOutOfCapacity = errors.New("buffer ran out of capacity")

// Fixed is a fixed-capacity implementation of TextBuffer and DataBuffer.
type Fixed struct {
	b []byte
}

func NewFixed(b []byte) *Fixed     { return &Fixed{b} }
func (f *Fixed) Bytes() []byte     { return f.b }
func (f *Fixed) Pos() int32        { return int32(len(f.b)) }
func (f *Fixed) PutByte(b byte)    { f.Extend(1)[0] = b }
func (f *Fixed) PutBytes(b []byte) { copy(f.Extend(len(b)), b) }

func (f *Fixed) Extend(n int) []byte {
	offset := len(f.b)
	if size := offset + n; size <= cap(f.b) {
		f.b = f.b[:size]
	} else {
		panic(errOutOfCapacity)
	}
	return f.b[offset:]
}

func (f *Fixed) ResizeBytes(n int) []byte {
	if n <= cap(f.b) {
		f.b = f.b[:n]
	} else {
		panic(errOutOfCapacity)
	}
	return f.b
}
