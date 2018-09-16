// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dump

import (
	"github.com/bnagy/gapstone"
)

const (
	csArch   = gapstone.CS_ARCH_ARM64
	csMode   = gapstone.CS_MODE_LITTLE_ENDIAN
	csSyntax = gapstone.CS_OPT_SYNTAX_DEFAULT
	padInsn  = gapstone.ARM64_INS_BRK
)

func rewriteText(insns []gapstone.Instruction, targets map[uint]string, textAddr uintptr, firstFuncAddr uint) {
}
