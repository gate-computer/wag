// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"testing"

	"github.com/tsavola/wag/abi"
)

func TestTypeScale(t *testing.T) {
	if s := TypeScale(abi.I32); s != Scale2 {
		t.Errorf("TypeScale(abi.I32) = 0x%x", s)
	}
	if s := TypeScale(abi.I64); s != Scale3 {
		t.Errorf("TypeScale(abi.I64) = 0x%x", s)
	}
}
