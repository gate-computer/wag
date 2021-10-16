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
	R binary.Reader
}

func (load L) Into(buf []byte) {
	if _, err := io.ReadFull(load.R, buf); err != nil {
		panic(err)
	}
}

func (load L) String(n uint32, name string) string {
	return String(load.Bytes(n), name)
}

func (load L) Bytes(n uint32) (data []byte) {
	data = make([]byte, n)
	load.Into(data)
	return
}

func (load L) Byte() byte {
	x, err := load.R.ReadByte()
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Uint32() uint32 {
	x, _, err := binary.Uint32(load.R)
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Uint64() uint64 {
	x, _, err := binary.Uint64(load.R)
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Varint7() int8 {
	x, _, err := binary.Varint7(load.R)
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Varint32() int32 {
	x, _, err := binary.Varint32(load.R)
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Varint64() int64 {
	x, _, err := binary.Varint64(load.R)
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Varuint1() bool {
	x, _, err := binary.Varuint1(load.R)
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Varuint32() uint32 {
	x, _, err := binary.Varuint32(load.R)
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Varuint64() uint64 {
	x, _, err := binary.Varuint64(load.R)
	if err != nil {
		panic(err)
	}
	return x
}

// Count reads a varuint32 for iteration.
func (load L) Count(maxCount uint32, name string) []struct{} {
	count, _, err := binary.Varuint32(load.R)
	if err != nil {
		panic(err)
	}
	if count > maxCount {
		panic(module.Errorf("%s count is too large: 0x%x", name, count))
	}
	return make([]struct{}, int(count))
}

func String(b []byte, name string) string {
	if !utf8.Valid(b) {
		panic(module.Errorf("%s is not a valid UTF-8 string", name))
	}
	return string(b)
}
