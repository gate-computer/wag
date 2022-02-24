// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"gate.computer/wag/internal/gen/reg"
)

type (
	Mod   byte
	ModRO byte
	ModRM byte
)

const (
	ModMem       = Mod(0)
	ModMemDisp8  = Mod(64)
	ModMemDisp32 = Mod(128)
	ModReg       = Mod(192)
)

const (
	ModRMSIB = ModRM(4)
)

func dispModSize(disp int32) (mod Mod, size uint32) {
	var (
		bit32 = bit(uint32(disp+128) > 255)
		bit8  = bit(disp != 0) &^ bit32

		size4 = bit32 << 2
		size1 = bit8

		mod32 = bit32 << 7
		mod8  = bit8 << 6
	)

	mod = Mod(mod32 | mod8)
	size = size4 | size1
	return
}

func regRO(r reg.R) ModRO { return ModRO((r & 7) << 3) }
func regRM(r reg.R) ModRM { return ModRM(r & 7) }
