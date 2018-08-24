// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package code

import (
	"encoding/binary"
)

type Buffer interface {
	Bytes() []byte
	Extend(n int) []byte
	PutByte(byte)
	PutBytes([]byte)
}

// Buf is an optimized Buffer.  The cached length (Addr) avoids interface
// function calls.
type Buf struct {
	Buffer
	Addr int32
}

func (buf *Buf) Extend(n int) (b []byte) {
	b = buf.Buffer.Extend(n)
	buf.Addr += int32(n)
	return
}

func (buf *Buf) PutByte(x byte) {
	buf.Buffer.PutByte(x)
	buf.Addr++
}

func (buf *Buf) PutBytes(x []byte) {
	buf.Buffer.PutBytes(x)
	buf.Addr += int32(len(x))
}

func (buf *Buf) PutInt8(value int8) {
	buf.PutByte(uint8(value))
}

func (buf *Buf) PutInt16(value int16) {
	binary.LittleEndian.PutUint16(buf.Extend(2), uint16(value))
}

func (buf *Buf) PutInt32(value int32) {
	binary.LittleEndian.PutUint32(buf.Extend(4), uint32(value))
}

func (buf *Buf) PutInt64(value int64) {
	binary.LittleEndian.PutUint64(buf.Extend(8), uint64(value))
}
