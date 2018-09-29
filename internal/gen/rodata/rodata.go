// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rodata

import (
	"github.com/tsavola/wag/wa"
)

const (
	// Masks are 16-byte aligned for x86-64 SSE.
	Mask7fOffset32 = iota * 16
	Mask7fOffset64
	Mask80Offset32
	Mask80Offset64
	Mask5f00Offset32 // 01011111000000000000000000000000
	Mask43e0Offset64 // 0100001111100000000000000000000000000000000000000000000000000000
	TableOffset
)

type MaskBaseOffset int32

const (
	Mask7fBase    = MaskBaseOffset(Mask7fOffset32)
	Mask80Base    = MaskBaseOffset(Mask80Offset32)
	MaskTruncBase = MaskBaseOffset(Mask5f00Offset32)
)

// MaskAddr calculates the text address for reading a mask for the given type
// size.  maskBaseOffset should be one of the Mask*Base constants.
// commonRODataAddr is the ISA-specific location of the common read-only data.
func MaskAddr(commonRODataAddr int32, maskBaseOffset MaskBaseOffset, t wa.Type) int32 {
	return commonRODataAddr + int32(maskBaseOffset) + int32((t.Size()&8)<<1)
}
