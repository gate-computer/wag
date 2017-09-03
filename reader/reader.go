// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reader

import (
	"io"
)

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader interface {
	io.Reader
	io.ByteScanner
}
