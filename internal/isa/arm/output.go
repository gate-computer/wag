// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen"
)

type output struct {
	buf   [16]uint32
	index uint8
}

func (o *output) size() int {
	return int(o.index * 4)
}

func (o *output) copy(target []byte) {
	for i := uint8(0); i < o.index; i++ {
		binary.LittleEndian.PutUint32(target, o.buf[i])
		target = target[4:]
	}
}

func (o *output) addr(text *code.Buf) int32 {
	return text.Addr + int32(o.index*4)
}

func (o *output) mapCallAddr(f *gen.Func) {
	f.MapCallAddr(f.Text.Addr + int32(o.index*4))
}

func (o *output) uint32(i uint32) {
	o.buf[o.index] = i
	o.index++
}
