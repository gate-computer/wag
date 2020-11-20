// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loader

import (
	"encoding/binary"
	"io"

	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/reader"
)

// L provides panicking alternatives for reader.R methods, and then some.
type L struct {
	R reader.R
}

func (load L) Into(buf []byte) {
	if _, err := io.ReadFull(load.R, buf); err != nil {
		panic(err)
	}
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

func (load L) Uint32() (x uint32) {
	if err := binary.Read(load.R, binary.LittleEndian, &x); err != nil {
		panic(err)
	}
	return
}

func (load L) Uint64() (x uint64) {
	if err := binary.Read(load.R, binary.LittleEndian, &x); err != nil {
		panic(err)
	}
	return
}

func (load L) Varint7() int8 {
	return int8(load.Varint64())
}

func (load L) Varint32() int32 {
	return int32(load.Varint64())
}

func (load L) Varint64() (x int64) {
	var shift uint
	for {
		b := load.Byte()
		x |= (int64(b) & 0x7f) << shift
		shift += 7
		if (b & 0x80) == 0 {
			if shift < 64 && (b&0x40) != 0 {
				x |= -1 << shift
			}
			return
		}
	}
}

func (load L) Varuint1() bool {
	x, err := load.R.ReadByte()
	if err != nil {
		panic(err)
	}
	if x > 1 {
		panic(module.Errorf("varuint1 is too large: 0x%x", x))
	}
	return x == 1
}

func (load L) Varuint32() (x uint32) {
	var shift uint
	for n := 1; ; n++ {
		b, err := load.R.ReadByte()
		if err != nil {
			panic(err)
		}
		if b < 0x80 {
			if n > 5 || n == 5 && b > 0xf {
				panic(module.Error("varuint32 is too large"))
			}
			return x | uint32(b)<<shift
		}
		x |= (uint32(b) & 0x7f) << shift
		shift += 7
	}
}

func (load L) Varuint64() (x uint64) {
	var shift uint
	for n := 1; ; n++ {
		b, err := load.R.ReadByte()
		if err != nil {
			panic(err)
		}
		if b < 0x80 {
			if n > 9 || n == 9 && b > 1 {
				panic(module.Error("varuint64 is too large"))
			}
			return x | uint64(b)<<shift
		}
		x |= (uint64(b) & 0x7f) << shift
		shift += 7
	}
}

// Count reads a varuint32 for iteration.
func (load L) Count(maxCount uint32, name string) []struct{} {
	count := load.Varuint32()
	if count > maxCount {
		panic(module.Errorf("%s count is too large: 0x%x", name, count))
	}
	return make([]struct{}, int(count))
}

func Varuint32(r reader.R) (x uint32, n int, err error) {
	var shift uint
	for n = 1; ; n++ {
		var b byte
		b, err = r.ReadByte()
		if err != nil {
			return
		}
		if b < 0x80 {
			if n > 5 || n == 5 && b > 0xf {
				err = module.Error("varuint32 is too large")
				return
			}
			x |= uint32(b) << shift
			return
		}
		x |= (uint32(b) & 0x7f) << shift
		shift += 7
	}
}
