// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 && !wagamd64

package amd64

import (
	"golang.org/x/sys/cpu"
)

var (
	haveLZCNT  = cpu.X86.HasBMI1 && cpu.X86.HasPOPCNT // Intel && AMD
	havePOPCNT = cpu.X86.HasPOPCNT
	haveTZCNT  = cpu.X86.HasBMI1
)
