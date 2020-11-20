// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stack provides runtime call stack manipulation functions.
package stack

import (
	"encoding/binary"

	"gate.computer/wag/internal/obj"
)

func InitFrame(startFuncAddr, entryFuncAddr uint32) (frame []byte) {
	frame = make([]byte, obj.Word*2)
	binary.LittleEndian.PutUint64(frame[0:], uint64(startFuncAddr))
	binary.LittleEndian.PutUint64(frame[8:], uint64(entryFuncAddr))
	return
}
