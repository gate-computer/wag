// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !amd64

package x86

import (
	"encoding/binary"
)

func (X86) PutUint32(b []byte, val uint32) { atomicPutUint32(b, val) }
func atomicPutUint32(b []byte, val uint32) { binary.LittleEndian.PutUint32(b, val) }
