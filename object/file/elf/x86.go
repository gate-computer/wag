// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wagamd64 amd64,!wagarm64

package elf

import (
	"debug/elf"
)

const elfMachine = elf.EM_X86_64
