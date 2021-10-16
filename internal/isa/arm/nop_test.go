// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build arm64 && !cgo
// +build arm64,!cgo

package arm

import (
	"testing"
)

func Test(t *testing.T) {
	t.Skip("tests require cgo")
}
