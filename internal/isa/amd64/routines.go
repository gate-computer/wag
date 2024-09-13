// Copyright (c) 2024 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64

package amd64

import (
	_ "embed"

	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/isa/amd64/in"
	"gate.computer/wag/trap"
)

func (MacroAssembler) Routines(p *gen.Prog) {
	p.MemoryCopyAddr = memoryRoutine(p, memorycopy)
	p.MemoryFillAddr = memoryRoutine(p, memoryfill)
}

func memoryRoutine(p *gen.Prog, bin []byte) int32 {
	asm.AlignFunc(p)
	addr := p.Text.Addr

	getCurrentMemoryPages(&p.Text)

	copy(p.Text.Extend(len(bin)), bin)

	in.JNEcd.Addr32(&p.Text, p.TrapLinks[trap.MemoryAccessOutOfBounds].Addr)

	// TODO: check suspend (resume after call)

	in.RET.Simple(&p.Text)

	return addr
}

//go:generate x86_64-linux-gnu-as -o memorycopy.o memorycopy.S
//go:generate x86_64-linux-gnu-ld -o memorycopy.elf memorycopy.o
//go:generate x86_64-linux-gnu-objcopy -O binary memorycopy.elf memorycopy.bin
//go:embed memorycopy.bin
var memorycopy []byte

//go:generate x86_64-linux-gnu-as -o memoryfill.o memoryfill.S
//go:generate x86_64-linux-gnu-ld -o memoryfill.elf memoryfill.o
//go:generate x86_64-linux-gnu-objcopy -O binary memoryfill.elf memoryfill.bin
//go:embed memoryfill.bin
var memoryfill []byte
