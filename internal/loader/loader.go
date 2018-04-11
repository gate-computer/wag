// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loader

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/tsavola/wag/internal/module"
)

// L provides panicking alternatives for module.Reader methods, and then some.
type L struct {
	module.Reader
}

func (load L) Into(buf []byte) {
	if _, err := io.ReadFull(load, buf); err != nil {
		panic(err)
	}
}

func (load L) Bytes(n uint32) (data []byte) {
	data = make([]byte, n)
	load.Into(data)
	return
}

func (load L) Byte() byte {
	x, err := load.ReadByte()
	if err != nil {
		panic(err)
	}
	return x
}

func (load L) Uint32() (x uint32) {
	if err := binary.Read(load, binary.LittleEndian, &x); err != nil {
		panic(err)
	}
	return
}

func (load L) Uint64() (x uint64) {
	if err := binary.Read(load, binary.LittleEndian, &x); err != nil {
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
	x, err := load.ReadByte()
	if err != nil {
		panic(err)
	}
	if x > 1 {
		panic(fmt.Errorf("varuint1 is too large: 0x%x", x))
	}
	return x == 1
}

func (load L) Varuint32() uint32 {
	x, err := binary.ReadUvarint(load)
	if err != nil {
		panic(err)
	}
	if x > math.MaxUint32 {
		panic(fmt.Errorf("varuint32 is too large: 0x%x", x))
	}
	return uint32(x)
}

func (load L) Varuint64() (x uint64) {
	x, err := binary.ReadUvarint(load)
	if err != nil {
		panic(err)
	}
	return
}

// Count reads a varuint32 for iteration.
func (load L) Count() []struct{} {
	count := load.Varuint32()
	if count > math.MaxInt32 {
		panic(fmt.Errorf("count is too large: 0x%x", count))
	}
	return make([]struct{}, int(count))
}
