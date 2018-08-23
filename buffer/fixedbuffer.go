// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffer

// Fixed is a fixed-capacity implementation of TextBuffer and DataBuffer.
type Fixed struct {
	b []byte
}

func NewFixed(b []byte) *Fixed     { return &Fixed{b} }
func (f *Fixed) Bytes() []byte     { return f.b }
func (f *Fixed) PutByte(b byte)    { f.Extend(1)[0] = b }
func (f *Fixed) PutBytes(b []byte) { copy(f.Extend(len(b)), b) }

func (f *Fixed) Extend(n int) []byte {
	b := f.b
	offset := len(b)
	b = b[:offset+n]
	f.b = b
	return b[offset:]
}

func (f *Fixed) ResizeBytes(n int) []byte {
	b := f.b
	b = b[:n]
	f.b = b
	return b
}
