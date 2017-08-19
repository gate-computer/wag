// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sections

import (
	"encoding/binary"
	"io"
)

type storer struct {
	io.Writer
}

func (store storer) Byte(b byte) {
	if _, err := store.Write([]byte{b}); err != nil {
		panic(err)
	}
}

func (store storer) Varuint32(x uint32) {
	buf := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(buf, uint64(x))
	if _, err := store.Write(buf[:n]); err != nil {
		panic(err)
	}
}
