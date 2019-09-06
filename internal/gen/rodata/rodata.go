// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rodata

import (
	"github.com/tsavola/wag/wa"
)

const CommonsAddr = 128

const (
	// Masks are 16-byte aligned for x86-64 SSE.
	Mask7fAddr32 = CommonsAddr + iota*16
	Mask7fAddr64
	Mask80Addr32
	Mask80Addr64
	Mask5f00Addr32 // 01011111000000000000000000000000
	Mask43e0Addr64 // 0100001111100000000000000000000000000000000000000000000000000000
	TableAddr
)

type MaskBaseAddr int32

const (
	Mask7fBase    = MaskBaseAddr(Mask7fAddr32)
	Mask80Base    = MaskBaseAddr(Mask80Addr32)
	MaskTruncBase = MaskBaseAddr(Mask5f00Addr32)
)

// MaskAddr calculates the text address for reading a mask for the given type
// size.  maskBaseAddr should be one of the Mask*Base constants.
func MaskAddr(maskBaseAddr MaskBaseAddr, t wa.Type) int32 {
	return int32(maskBaseAddr) + int32((t.Size()&8)<<1)
}
