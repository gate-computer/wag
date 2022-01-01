// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64
// +build amd64

package amd64

import (
	"golang.org/x/sys/cpu"
)

func haveLZCNT() bool  { return cpu.X86.HasBMI1 && cpu.X86.HasPOPCNT } // Intel && AMD
func havePOPCNT() bool { return cpu.X86.HasPOPCNT }
func haveTZCNT() bool  { return cpu.X86.HasBMI1 }
