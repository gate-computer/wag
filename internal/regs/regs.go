// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regs

import (
	"fmt"

	"github.com/tsavola/wag/abi"
)

type R byte

func (reg R) String() string {
	return fmt.Sprintf("r%d", reg)
}

const (
	Result = R(0)
)

func Bitmap(cat abi.Category, regs *[]R, available ...bool) (mask uint64) {
	for i, set := range available {
		if set {
			mask |= uint64(1) << (uint8(i<<1) + uint8(cat))
			*regs = append(*regs, R(i))
		}
	}
	return
}
