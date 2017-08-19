// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"github.com/tsavola/wag/internal/x86"
)

const (
	machNative            = x86.Native
	machFunctionAlignment = x86.FunctionAlignment
	machPaddingByte       = x86.PaddingByte
	machResultReg         = x86.ResultReg
)

var mach x86.X86
