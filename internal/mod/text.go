// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mod

import (
	"encoding/binary"
)

type TextBuffer interface {
	Bytes() []byte
	Extend(n int) []byte
	PutByte(byte)
	PutBytes([]byte)
}

type Text struct {
	B TextBuffer

	pos int32
}

func (text *Text) Pos() int32 {
	return text.pos
}

func (text *Text) Bytes() []byte {
	return text.B.Bytes()
}

func (text *Text) Extend(n int) (b []byte) {
	b = text.B.Extend(n)
	text.pos += int32(n)
	return
}

func (text *Text) PutByte(x byte) {
	text.B.PutByte(x)
	text.pos++
}

func (text *Text) PutBytes(x []byte) {
	text.B.PutBytes(x)
	text.pos += int32(len(x))
}

func (text *Text) PutInt8(value int8) {
	text.PutByte(uint8(value))
}

func (text *Text) PutInt16(value int16) {
	binary.LittleEndian.PutUint16(text.Extend(2), uint16(value))
}

func (text *Text) PutInt32(value int32) {
	binary.LittleEndian.PutUint32(text.Extend(4), uint32(value))
}

func (text *Text) PutInt64(value int64) {
	binary.LittleEndian.PutUint64(text.Extend(8), uint64(value))
}
