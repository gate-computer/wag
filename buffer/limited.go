// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffer

// Limited is a dynamic buffer with a maximum size.  The default value is an
// empty buffer that cannot grow.
type Limited struct {
	d Dynamic
}

// NewLimited buffer with a maximum size.  It is initially empty (b is
// truncated).
func NewLimited(b []byte, maxSize int) *Limited {
	return &Limited{Dynamic{b[:0], maxSize}}
}

// Bytes doesn't panic.
func (l *Limited) Bytes() []byte {
	return l.d.Bytes()
}

// PutByte panics with ErrSizeLimit if the buffer is already full.
func (l *Limited) PutByte(value byte) {
	if len(l.d.buf) >= l.d.maxSize {
		panic(ErrSizeLimit)
	}
	l.d.PutByte(value)
}

// Extend panics with ErrSizeLimit if n bytes cannot be appended to the buffer.
func (l *Limited) Extend(n int) []byte {
	if len(l.d.buf)+n > l.d.maxSize {
		panic(ErrSizeLimit)
	}
	return l.d.Extend(n)
}

// ResizeBytes panics with ErrSizeLimit if n is larger than maximum buffer
// size.
func (l *Limited) ResizeBytes(n int) []byte {
	if n > l.d.maxSize {
		panic(ErrSizeLimit)
	}
	return l.d.ResizeBytes(n)
}
