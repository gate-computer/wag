// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/trap"
)

type trampoline struct {
	stackOffset int32
	link        links.L
}

// opTrapCall generates exactly one call instruction.  (Update ISA
// implementations if that ever changes.)
func opTrapCall(f *function, id trap.Id) {
	t := &f.trapTrampolines[id]
	t.stackOffset = f.stackOffset
	t.link.Addr = f.Text.Pos()
	opCall(f, &f.TrapLinks[id])
}

func trapTrampolineAddr(f *function, id trap.Id) (addr int32) {
	t := &f.trapTrampolines[id]
	if t.stackOffset == f.stackOffset {
		addr = t.link.Addr
	}
	return
}
