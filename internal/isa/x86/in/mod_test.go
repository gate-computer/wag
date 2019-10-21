// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"testing"
)

func TestDispModSize(t *testing.T) {
	for _, pair := range [][3]int{
		{-0x80000000, int(ModMemDisp32), 4},
		{-0x7fffffff, int(ModMemDisp32), 4},
		{-0x10000, int(ModMemDisp32), 4},
		{-0x82, int(ModMemDisp32), 4},
		{-0x81, int(ModMemDisp32), 4},
		{-0x80, int(ModMemDisp8), 1},
		{-0x7f, int(ModMemDisp8), 1},
		{-2, int(ModMemDisp8), 1},
		{-1, int(ModMemDisp8), 1},
		{0, int(ModMem), 0},
		{1, int(ModMemDisp8), 1},
		{2, int(ModMemDisp8), 1},
		{0x7e, int(ModMemDisp8), 1},
		{0x7f, int(ModMemDisp8), 1},
		{0x80, int(ModMemDisp32), 4},
		{0x81, int(ModMemDisp32), 4},
		{0xffff, int(ModMemDisp32), 4},
		{0x10000, int(ModMemDisp32), 4},
		{0x7ffffffe, int(ModMemDisp32), 4},
		{0x7fffffff, int(ModMemDisp32), 4},
	} {
		if mod, size := dispModSize(int32(pair[0])); mod != Mod(pair[1]) || size != uint32(pair[2]) {
			t.Errorf("dispModSize(%d) = %d, %d", pair[0], mod, size)
		}
	}
}
