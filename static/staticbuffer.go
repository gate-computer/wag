// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package static

import (
	"errors"
)

var errCapacity = errors.New("static buffer capacity exceeded")

// Buffer is a fixed-capacity implementation of compile.CodeBuffer and
// compile.DataBuffer.
type Buffer struct {
	b   []byte
	cap int
}

// Buf uses len(b) as the buffer's capacity.  The buffer is initially empty (b
// is truncated).
func Buf(b []byte) *Buffer { return &Buffer{b[:0], len(b)} }

func (f *Buffer) Bytes() []byte  { return f.b }
func (f *Buffer) PutByte(b byte) { f.Extend(1)[0] = b }

func (f *Buffer) Extend(n int) []byte {
	b := f.b
	offset := len(b)
	b = b[:offset+n]
	if len(b) > f.cap {
		panic(errCapacity)
	}
	f.b = b
	return b[offset:]
}

func (f *Buffer) ResizeBytes(n int) []byte {
	b := f.b
	b = b[:n]
	if len(b) > f.cap {
		panic(errCapacity)
	}
	f.b = b
	return b
}
