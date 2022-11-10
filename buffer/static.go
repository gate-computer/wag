// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffer

import (
	"encoding/binary"
	"io"

	"import.name/pan"
)

// Static is a fixed-capacity buffer, for wrapping a memory-mapped region.  The
// default value is a zero-capacity buffer.
type Static struct {
	buf []byte
}

// MakeStatic buffer.
//
// This function can be used in field initializer expressions.  The initialized
// field must not be copied.
func MakeStatic(b []byte) Static {
	return Static{b}
}

// NewStatic buffer.
func NewStatic(b []byte) *Static {
	s := MakeStatic(b)
	return &s
}

// Capacity of the static buffer.
func (s *Static) Cap() int {
	return cap(s.buf)
}

// Len doesn't panic.
func (s *Static) Len() int {
	return len(s.buf)
}

// Bytes doesn't panic.
func (s *Static) Bytes() []byte {
	return s.buf
}

// Write doesn't panic.
func (s *Static) Write(b []byte) (n int, err error) {
	offset := len(s.buf)
	size := offset + len(b)
	if size <= cap(s.buf) {
		s.buf = s.buf[:size]
	} else {
		s.buf = s.buf[:cap(s.buf)]
		err = io.EOF
	}
	n = copy(s.buf[offset:], b)
	return
}

// PutByte panics with ErrSizeLimit if the buffer is already full.
func (s *Static) PutByte(value byte) {
	offset := len(s.buf)
	if offset >= cap(s.buf) {
		pan.Panic(ErrSizeLimit)
	}
	s.buf = s.buf[:offset+1]
	s.buf[offset] = value
}

// Extend panics with ErrSizeLimit if 4 bytes cannot be appended to the buffer.
func (s *Static) PutUint32(i uint32) {
	binary.LittleEndian.PutUint32(s.Extend(4), i)
}

// Extend panics with ErrSizeLimit if n bytes cannot be appended to the buffer.
func (s *Static) Extend(n int) []byte {
	offset := len(s.buf)
	size := offset + n
	if size > cap(s.buf) {
		pan.Panic(ErrSizeLimit)
	}
	s.buf = s.buf[:size]
	return s.buf[offset:]
}

// ResizeBytes panics with ErrSizeLimit if n is larger than buffer capacity.
func (s *Static) ResizeBytes(n int) []byte {
	if n > cap(s.buf) {
		pan.Panic(ErrSizeLimit)
	}
	s.buf = s.buf[:n]
	return s.buf
}
