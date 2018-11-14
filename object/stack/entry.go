// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stack provides runtime call stack manipulation functions.
package stack

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/obj"
)

func EntryFrame(entryFuncAddr uint32, entryArgs []uint64) (frame []byte) {
	frame = make([]byte, obj.Word+len(entryArgs)*obj.Word)
	setupEntryFrame(frame, entryFuncAddr, entryArgs)
	return
}

func SetupEntryFrame(stack []byte, entryFuncAddr uint32, entryArgs []uint64) (frameSize int) {
	frameSize = obj.Word + len(entryArgs)*obj.Word
	setupEntryFrame(stack[len(stack)-frameSize:], entryFuncAddr, entryArgs)
	return
}

func setupEntryFrame(b []byte, addr uint32, args []uint64) {
	binary.LittleEndian.PutUint64(b, uint64(addr))

	for i := len(args) - 1; i >= 0; i-- {
		b = b[obj.Word:]
		binary.LittleEndian.PutUint64(b, args[i])
	}
}
