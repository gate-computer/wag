// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64

package arm64

import (
	"encoding/binary"

	"gate.computer/wag/internal/code"
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
