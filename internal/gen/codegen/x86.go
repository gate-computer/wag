// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wag_amd64 amd64,!wag_arm64

package codegen

import (
	"github.com/tsavola/wag/internal/isa/x86"
)

var isa x86.ISA
