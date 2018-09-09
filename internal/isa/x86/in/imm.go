// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

func immSize(val int32) uint8 {
	var (
		bit32 = bit(uint32(val+128) > 255)
		scale = bit32 << 1
	)

	return 1 << scale
}

func immOpcodeSize(ops uint16, val int32) (op byte, size uint8) {
	var (
		bit32 = bit(uint32(val+128) > 255)
		opPos = bit32 << 3
		scale = bit32 << 1
	)

	op = byte(ops >> opPos)
	size = 1 << scale
	return
}
