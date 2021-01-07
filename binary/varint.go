// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package binary implements WebAssembly integer decoding.
//
// The Reader interface is overly specific as a performance optimization; see
// https://savo.la/sneaky-go-interface-conversion.html for background.
package binary

import (
	"encoding/binary"
	"io"
)

// Reader is appropriate for decoding WebAssembly modules.
type Reader interface {
	io.Reader
	io.ByteScanner
}

// Uint32 reads a little-endian value.  The number of bytes read is also
// returned (4 if successful).
func Uint32(r Reader) (uint32, int, error) {
	b := make([]byte, 4)

	n, err := io.ReadFull(r, b)
	if err != nil {
		return 0, n, err
	}

	return binary.LittleEndian.Uint32(b), n, nil
}

// Uint64 reads a little-endian value.  The number of bytes read is also
// returned (8 if successful).
func Uint64(r Reader) (uint64, int, error) {
	b := make([]byte, 8)

	n, err := io.ReadFull(r, b)
	if err != nil {
		return 0, n, err
	}

	return binary.LittleEndian.Uint64(b), n, nil
}

// Varuint1 reads a bit (in a byte).  The number of bytes read is also returned
// (0 or 1).
func Varuint1(r Reader) (bool, int, error) {
	var n int

	b, err := r.ReadByte()
	if err != nil {
		return false, n, err
	}
	n++

	if b > 1 {
		return false, n, moduleError("varuint1 value is too large")
	}
	return b == 1, n, nil
}

// Varint7 reads a byte using the variable-length encoding for signed integers.
// The number of bytes read is also returned (0 or 1).
func Varint7(r Reader) (int8, int, error) {
	var n int

	b, err := r.ReadByte()
	if err != nil {
		return 0, n, err
	}
	n++

	if b&0x80 != 0 {
		return 0, n, moduleError("varint7 encoding is too long")
	}
	if b&0x40 != 0 {
		b |= 0x80
	}
	return int8(b), n, nil
}

// Varint32 reads variably encoded value.  The number of bytes read is also
// returned.
func Varint32(r Reader) (int32, int, error) {
	var x int32
	var n int
	var shift uint

	for n < 5 {
		b, err := r.ReadByte()
		if err != nil {
			return x, n, err
		}
		n++

		x |= (int32(b) & 0x7f) << shift
		shift += 7

		if b&0x80 == 0 {
			neg := b&0x40 != 0
			if n == 5 {
				if !neg {
					if b > 7 {
						return 0, n, moduleError("varint32 value is too large")
					}
				} else {
					if b < 0x78 {
						return 0, n, moduleError("varint32 value is too small")
					}
				}
			} else {
				if neg {
					x |= -1 << shift
				}
			}
			return x, n, nil
		}
	}

	return 0, n, moduleError("varint32 encoding is too long")
}

// Varint64 reads variably encoded value.  The number of bytes read is also
// returned.
func Varint64(r Reader) (int64, int, error) {
	var x int64
	var n int
	var shift uint

	for n < 10 {
		b, err := r.ReadByte()
		if err != nil {
			return x, n, err
		}
		n++

		x |= (int64(b) & 0x7f) << shift
		shift += 7

		if b&0x80 == 0 {
			neg := b&0x40 != 0
			if n == 10 {
				if !neg {
					if b != 0 {
						return 0, n, moduleError("varint64 value is too large")
					}
				} else {
					if b != 0x7f {
						return 0, n, moduleError("varint64 value is too small")
					}
				}
			} else {
				if neg {
					x |= -1 << shift
				}
			}
			return x, n, nil
		}
	}

	return 0, n, moduleError("varint64 encoding is too long")
}

// Varuint32 reads variably encoded value.  The number of bytes read is also
// returned (up to 5).
func Varuint32(r Reader) (uint32, int, error) {
	var x uint32
	var n int
	var shift uint

	for n < 5 {
		b, err := r.ReadByte()
		if err != nil {
			return x, n, err
		}
		n++

		if b < 0x80 {
			if n == 5 && b > 0xf {
				return 0, n, moduleError("varuint32 value is too large")
			}
			return x | uint32(b)<<shift, n, nil
		}

		x |= (uint32(b) & 0x7f) << shift
		shift += 7
	}

	return 0, n, moduleError("varuint32 encoding is too long")
}

// Varuint64 reads variably encoded value.  The number of bytes read is also
// returned (up to 10).
func Varuint64(r Reader) (uint64, int, error) {
	var x uint64
	var n int
	var shift uint

	for n < 10 {
		b, err := r.ReadByte()
		if err != nil {
			return x, n, err
		}
		n++

		if b < 0x80 {
			if n == 10 && b > 1 {
				return 0, n, moduleError("varuint64 value is too large")
			}
			return x | uint64(b)<<shift, n, nil
		}

		x |= (uint64(b) & 0x7f) << shift
		shift += 7
	}

	return 0, n, moduleError("varuint64 encoding is too long")
}

type moduleError string

func (e moduleError) Error() string       { return string(e) }
func (e moduleError) PublicError() string { return string(e) }
func (e moduleError) ModuleError()        {}
