// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package count

import (
	"gate.computer/wag/binary"
)

type Reader struct {
	R binary.Reader
	N uint32
}

func (r *Reader) Read(b []byte) (n int, err error) {
	n, err = r.R.Read(b)
	r.N += uint32(n)
	return
}

func (r *Reader) ReadByte() (b byte, err error) {
	b, err = r.R.ReadByte()
	if err == nil {
		r.N++
	}
	return
}

func (r *Reader) UnreadByte() (err error) {
	err = r.R.UnreadByte()
	if err == nil {
		r.N--
	}
	return
}

func (r *Reader) Tell() int64 {
	return int64(r.N)
}
