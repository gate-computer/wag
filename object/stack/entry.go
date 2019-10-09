// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stack provides runtime call stack manipulation functions.
package stack

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/obj"
)

func EntryFrame(entryFuncAddr uint32) (frame []byte) {
	frame = make([]byte, obj.Word)
	binary.LittleEndian.PutUint64(frame, uint64(entryFuncAddr))
	return
}
