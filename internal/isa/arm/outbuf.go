// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/code"
)

type outbuf struct {
	buf  [128]byte
	size int
}

func (o outbuf) copy(dest []byte) {
	copy(dest, o.buf[:])
}

func (o outbuf) addr(text *code.Buf) int32 {
	return text.Addr + int32(o.size)
}

func (o *outbuf) insn(i uint32) {
	binary.LittleEndian.PutUint32(o.buf[o.size:], i)
	o.size += 4
}
