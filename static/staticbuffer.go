// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package static

// Buffer is a fixed-capacity implementation of compile.CodeBuffer and
// compile.DataBuffer.
type Buffer struct {
	b []byte
}

// Buf truncates the length of b to zero.  (This function is not called
// NewBuffer because it has different semantics than the stdlib functions.)
func Buf(b []byte) *Buffer { return &Buffer{b[:0]} }

func (f *Buffer) Bytes() []byte  { return f.b }
func (f *Buffer) PutByte(b byte) { f.Extend(1)[0] = b }

func (f *Buffer) Extend(n int) []byte {
	b := f.b
	offset := len(b)
	b = b[:offset+n]
	f.b = b
	return b[offset:]
}

func (f *Buffer) ResizeBytes(n int) []byte {
	b := f.b
	b = b[:n]
	f.b = b
	return b
}
