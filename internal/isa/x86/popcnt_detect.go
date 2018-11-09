// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64

package x86

import (
	"golang.org/x/sys/cpu"
)

func havePOPCNT() bool {
	return cpu.X86.HasPOPCNT
}
