// Copyright (c) 2024 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64

package arm64

import (
	_ "embed"

	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/isa/arm64/in"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Routines(p *gen.Prog) {
	p.MemoryCopyAddr = memoryRoutine(p, memorycopy)
	p.MemoryFillAddr = memoryRoutine(p, memoryfill)
}

func memoryRoutine(p *gen.Prog, bin []byte) int32 {
	addr := p.Text.Addr

	{
		var o outbuf
		o.insn(in.PushReg(RegLink, wa.I64))
		o.copy(p.Text.Extend(o.size))
	}

	getCurrentMemoryPages(&p.Text)

	copy(p.Text.Extend(len(bin)), bin)

	{
		var o outbuf
		o.insn(in.CBZ.RtI19(RegResult, 2, wa.Size32)) // Skip next instruction.
		o.insn(in.B.I26(in.Int26((p.TrapLinks[trap.MemoryAccessOutOfBounds].Addr - o.addr(&p.Text)) / 4)))
		// TODO: check suspend (resume after call)
		o.copy(p.Text.Extend(o.size))
	}

	asm.Return(p, 0)

	return addr
}

//go:generate aarch64-linux-gnu-as -o memorycopy.o memorycopy.S
//go:generate aarch64-linux-gnu-ld -o memorycopy.elf memorycopy.o
//go:generate aarch64-linux-gnu-objcopy -O binary memorycopy.elf memorycopy.bin
//go:embed memorycopy.bin
var memorycopy []byte

//go:generate aarch64-linux-gnu-as -o memoryfill.o memoryfill.S
//go:generate aarch64-linux-gnu-ld -o memoryfill.elf memoryfill.o
//go:generate aarch64-linux-gnu-objcopy -O binary memoryfill.elf memoryfill.bin
//go:embed memoryfill.bin
var memoryfill []byte
