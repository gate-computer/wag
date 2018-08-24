// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"github.com/tsavola/wag/abi"
)

const (
	// Masks are 16-byte aligned for x86-64 SSE.
	ROMask7fAddr32 = iota * 16
	ROMask7fAddr64
	ROMask80Addr32
	ROMask80Addr64
	ROMask5f00Addr32 // 01011111000000000000000000000000
	ROMask43e0Addr64 // 0100001111100000000000000000000000000000000000000000000000000000
	ROTableAddr
)

type MaskBaseAddr int32

const (
	Mask7fBase    = MaskBaseAddr(ROMask7fAddr32)
	Mask80Base    = MaskBaseAddr(ROMask80Addr32)
	MaskTruncBase = MaskBaseAddr(ROMask5f00Addr32)
)

// MaskAddr calculates the absolute read-only data address for reading a mask
// for the given type size.  maskBaseAddr should be one of the Mask*Base
// constants.
func MaskAddr(roDataAddr int32, maskBaseAddr MaskBaseAddr, t abi.Type) int32 {
	return roDataAddr + int32(maskBaseAddr) + int32((t.Size()&8)<<1)
}
