// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loader

import (
	"io"
	"unicode/utf8"

	"gate.computer/wag/binary"
	"gate.computer/wag/internal/module"
)

// L provides panicking reading and integer decoding methods.
type L struct {
	r binary.Reader
	n int64
}

func New(r binary.Reader) *L {
	return &L{r: r}
}

// Tell how many bytes have been read.
func (load *L) Tell() int64 {
	return load.n
}

// Read doesn't panic, but returns an error.
func (load *L) Read(buf []byte) (int, error) {
	n, err := load.r.Read(buf)
	load.n += int64(n)
	return n, err
}

// ReadByte doesn't panic, but returns an error.
func (load *L) ReadByte() (byte, error) {
	x, err := load.r.ReadByte()
	if err == nil {
		load.n++
	}
	return x, err
}

// UnreadByte doesn't panic, but returns an error.
func (load *L) UnreadByte() error {
	err := load.r.UnreadByte()
	if err == nil {
		load.n--
	}
	return err
}

func (load *L) Into(buf []byte) {
	n, err := io.ReadFull(load.r, buf)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
}

func (load *L) String(n uint32, name string) string {
	return String(load.Bytes(n), name)
}

func (load *L) Bytes(n uint32) (data []byte) {
	data = make([]byte, n)
	load.Into(data)
	return
}

func (load *L) Byte() byte {
	x, err := load.ReadByte()
	if err != nil {
		check(err)
	}
	return x
}

func (load *L) Uint32() uint32 {
	x, n, err := binary.Uint32(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	return x
}

func (load *L) Uint64() uint64 {
	x, n, err := binary.Uint64(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	return x
}

func (load *L) Varint7() int8 {
	x, n, err := binary.Varint7(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	return x
}

func (load *L) Varint32() int32 {
	x, n, err := binary.Varint32(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	return x
}

func (load *L) Varint64() int64 {
	x, n, err := binary.Varint64(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	return x
}

func (load *L) Varuint1() bool {
	x, n, err := binary.Varuint1(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	return x
}

func (load *L) Varuint32() uint32 {
	x, n, err := binary.Varuint32(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	return x
}

func (load *L) Varuint64() uint64 {
	x, n, err := binary.Varuint64(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	return x
}

// Count reads a varuint32.
func (load *L) Count(max int, name string) int {
	count, n, err := binary.Varuint32(load.r)
	load.n += int64(n)
	if err != nil {
		check(err)
	}
	if uint64(count) > uint64(max) {
		check(module.Errorf("%s count is too large: 0x%x", name, count))
	}
	return int(count)
}

// Span reads a varuint32 for iteration.
func (load *L) Span(max int, name string) []struct{} {
	return make([]struct{}, load.Count(max, name))
}

func String(b []byte, name string) string {
	if !utf8.Valid(b) {
		check(module.Errorf("%s is not a valid UTF-8 string", name))
	}
	return string(b)
}
