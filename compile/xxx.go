// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wagarm64 arm64,!wagamd64

package compile

import (
	"github.com/tsavola/wag/internal/isa/arm"
)

// XXX_SetRelLinkAddr will disappear without a warning.
func XXX_SetRelLinkAddr(x bool) {
	arm.XXX_RelLinkAddr = x
}
