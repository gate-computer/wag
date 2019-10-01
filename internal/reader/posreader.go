// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reader

type PosReader struct {
	R   R
	Pos uint32
}

func (pr *PosReader) Read(b []byte) (n int, err error) {
	n, err = pr.R.Read(b)
	pr.Pos += uint32(n)
	return
}

func (pr *PosReader) ReadByte() (b byte, err error) {
	b, err = pr.R.ReadByte()
	if err == nil {
		pr.Pos++
	}
	return
}

func (pr *PosReader) UnreadByte() (err error) {
	err = pr.R.UnreadByte()
	if err == nil {
		pr.Pos--
	}
	return
}
