// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reader

type Counter struct {
	R R
	N uint32
}

func (pr *Counter) Read(b []byte) (n int, err error) {
	n, err = pr.R.Read(b)
	pr.N += uint32(n)
	return
}

func (pr *Counter) ReadByte() (b byte, err error) {
	b, err = pr.R.ReadByte()
	if err == nil {
		pr.N++
	}
	return
}

func (pr *Counter) UnreadByte() (err error) {
	err = pr.R.UnreadByte()
	if err == nil {
		pr.N--
	}
	return
}

func (pr *Counter) Tell() int64 {
	return int64(pr.N)
}
