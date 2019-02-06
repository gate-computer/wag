// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffer

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// Dynamic is a variable-capacity buffer.  The default value is a valid buffer.
type Dynamic struct {
	buf     []byte
	maxSize int // For limiting allocation; not enforced by this implementation.
}

func makeDynamicHint(b []byte, maxSizeHint int) Dynamic {
	if len(b) != 0 {
		panic("slice must be empty")
	}
	return Dynamic{b, maxSizeHint}
}

// NewDynamic buffer.  The slice must be empty.
func NewDynamic(b []byte) *Dynamic {
	return NewDynamicHint(b, 0)
}

// NewDynamicHint avoids making excessive allocations if the maximum buffer
// size can be estimated in advance.  The slice must be empty.
func NewDynamicHint(b []byte, maxSizeHint int) *Dynamic {
	d := makeDynamicHint(b, maxSizeHint)
	return &d
}

// Len doesn't panic.
func (d *Dynamic) Len() int {
	return len(d.buf)
}

// Bytes doesn't panic.
func (d *Dynamic) Bytes() []byte {
	return d.buf
}

// PutBytes doesn't panic unless out of memory.
func (d *Dynamic) PutByte(value byte) {
	d.Extend(1)[0] = value
}

// Extend doesn't panic unless out of memory.
func (d *Dynamic) PutUint32(i uint32) {
	binary.LittleEndian.PutUint32(d.Extend(4), i)
}

// Extend doesn't panic unless out of memory.
func (d *Dynamic) Extend(addLen int) []byte {
	offset := len(d.buf)

	if size := offset + addLen; size <= cap(d.buf) {
		if size < offset { // Check for overflow
			panic(errors.New("buffer size out of range"))
		}

		d.buf = d.buf[:size]
	} else {
		d.grow(addLen)
	}

	return d.buf[offset:]
}

// ResizeBytes doesn't panic unless out of memory.
func (d *Dynamic) ResizeBytes(newLen int) []byte {
	if newLen <= cap(d.buf) {
		d.buf = d.buf[:newLen]
	} else {
		d.grow(newLen - len(d.buf))
	}

	return d.buf
}

func (d *Dynamic) grow(addLen int) {
	newLen := len(d.buf) + addLen

	newCap := cap(d.buf)*2 + addLen
	if newCap < cap(d.buf) { // Handle overflow
		newCap = newLen
	}

	if newCap > d.maxSize {
		if d.maxSize >= newLen { // Ignore it if we went over it
			newCap = d.maxSize
		}
	}

	newBuf := make([]byte, newLen, newCap)
	copy(newBuf, d.buf)
	d.buf = newBuf
}
