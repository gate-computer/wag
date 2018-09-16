// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package code

type Buffer interface {
	Bytes() []byte
	Extend(n int) []byte
	PutByte(byte)
	PutUint32(uint32) // Little-endian byte order.
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

func (buf *Buf) PutUint32(x uint32) {
	buf.Buffer.PutUint32(x)
	buf.Addr += 4
}
