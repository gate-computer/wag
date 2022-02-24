// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/wa"
)

type (
	Scale byte
	Index byte
	Base  byte
)

const (
	Scale0 = Scale(0 << 6)
	Scale1 = Scale(1 << 6)
	Scale2 = Scale(2 << 6)
	Scale3 = Scale(3 << 6)

	noIndex = Index(4 << 3)

	baseStack = Base(RegStack)
)

func TypeScale(t wa.Type) Scale { return Scale(t.Size()>>3|2) << 6 } // Scale2 or Scale3
func regIndex(r reg.R) Index    { return Index((r & 7) << 3) }
func regBase(r reg.R) Base      { return Base(r & 7) }
