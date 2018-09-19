// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"testing"

	"github.com/tsavola/wag/wa"
)

func TestTypeScale(t *testing.T) {
	if s := TypeScale(wa.I32); s != Scale2 {
		t.Errorf("TypeScale(wa.I32) = 0x%x", s)
	}
	if s := TypeScale(wa.I64); s != Scale3 {
		t.Errorf("TypeScale(wa.I64) = 0x%x", s)
	}
}
