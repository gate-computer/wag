// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"testing"
)

// Number formatting varies due to gapstone

var testImm8 = []int8{
	-128,
	-127,
	-2,
	-1,
	0,
	1,
	2,
	0x7e,
	0x7f,
}

var testDisp8 = map[int8]string{
	-128:  " - 0x80",
	-127:  " - 0x7f",
	-2:    " - 2",
	-1:    " - 1",
	0:     "",
	+1:    " + 1",
	+2:    " + 2",
	+0x7e: " + 0x7e",
	+0x7f: " + 0x7f",
}

var testImm16 = []int16{
	-32768,
	-32767,
	-128,
	-127,
	-2,
	-1,
	0,
	1,
	2,
	0x7e,
	0x7f,
	32766,
	32767,
}

var testImm32 = []int32{
	-0x80000000,
	-0x7fffffff,
	-0x10000,
	-0x82,
	-0x81,
	-128,
	-127,
	-2,
	-1,
	0,
	1,
	2,
	0x7e,
	0x7f,
	0x80,
	0x81,
	0xffff,
	0x10000,
	0x7ffffffe,
	0x7fffffff,
}

var testDisp32 = map[int32]string{
	-0x80000000: " - 0x80000000",
	-0x7fffffff: " - 0x7fffffff",
	-0x10000:    " - 0x10000",
	-0x82:       " - 0x82",
	-0x81:       " - 0x81",
	-128:        " - 0x80",
	-127:        " - 0x7f",
	-2:          " - 2",
	-1:          " - 1",
	0:           "",
	+1:          " + 1",
	+2:          " + 2",
	+0x7e:       " + 0x7e",
	+0x7f:       " + 0x7f",
	0x80:        " + 0x80",
	0x81:        " + 0x81",
	0xffff:      " + 0xffff",
	0x10000:     " + 0x10000",
	0x7ffffffe:  " + 0x7ffffffe",
	0x7fffffff:  " + 0x7fffffff",
}

var testImm64 = []int64{
	-0x8000000000000000,
	-0x7fffffffffffffff,
	-0x80000001,
	-0x80000000,
	-0x7fffffff,
	-0x10000,
	-0x82,
	-0x81,
	-128,
	-127,
	-2,
	-1,
	0,
	1,
	2,
	0x7e,
	0x7f,
	0x80,
	0x81,
	0xffff,
	0x10000,
	0x7ffffffe,
	0x7fffffff,
	0x80000000,
	0x7ffffffffffffffe,
	0x7fffffffffffffff,
}

func TestImm(t *testing.T) {
	for _, pair := range [][2]int{
		{-0x80000000, 4},
		{-0x7fffffff, 4},
		{-0x10000, 4},
		{-0x82, 4},
		{-0x81, 4},
		{-0x80, 1},
		{-0x7f, 1},
		{-2, 1},
		{-1, 1},
		{0, 1},
		{1, 1},
		{2, 1},
		{0x7e, 1},
		{0x7f, 1},
		{0x80, 4},
		{0x81, 4},
		{0xffff, 4},
		{0x10000, 4},
		{0x7ffffffe, 4},
		{0x7fffffff, 4},
	} {
		if size := immSize(int32(pair[0])); size != uint8(pair[1]) {
			t.Errorf("immSize(%d) = %d", pair[0], size)
		}

		op, size := immOpcodeSize(0xed67, int32(pair[0]))
		if size == uint8(pair[1]) {
			if size == 1 && op == 0x67 {
				continue
			}
			if size == 4 && op == 0xed {
				continue
			}
		}
		t.Errorf("immOpcodeSize(0xed67, %d) = %#x, %d", pair[0], op, size)
	}
}
