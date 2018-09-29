// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/atomic"
	"github.com/tsavola/wag/internal/gen/debug"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

func GenProgram(
	text code.Buffer,
	objMap obj.Map,
	load loader.L,
	m *module.M,
	entryIndex int,
	entryArgs []uint64,
	eventHandler func(event.Event),
) {
	funcStorage := gen.Func{
		Prog: gen.Prog{
			Module:    m,
			Text:      code.Buf{Buffer: text},
			Map:       objMap,
			FuncLinks: make([]link.FuncL, len(m.Funcs)),
		},
	}
	p := &funcStorage.Prog

	if debug.Enabled {
		if debug.Depth != 0 {
			debug.Printf("")
		}
		debug.Depth = 0
	}

	funcCodeCount := load.Varuint32()
	if needed := len(m.Funcs) - len(m.ImportFuncs); funcCodeCount != uint32(needed) {
		panic(fmt.Errorf("wrong number of function bodies: %d (should be: %d)", funcCodeCount, needed))
	}

	p.Map.InitObjectMap(len(m.ImportFuncs), int(funcCodeCount))

	asm.JumpToTrapHandler(p, trap.MissingFunction) // at zero address
	if p.Text.Addr == 0 || p.Text.Addr > 16 {
		panic("bad address after MissingFunction trap handler")
	}
	asm.Resume(p)
	if p.Text.Addr <= 16 || p.Text.Addr > 32 {
		panic("bad address after resume routine")
	}
	asm.Init(p)
	// after init, execution proceeds to start func, main func, or exit trap

	maxInitIndex := -1
	mainResultType := wa.Void

	if m.StartDefined {
		maxInitIndex = int(m.StartIndex)

		opInitialCall(p, &p.FuncLinks[m.StartIndex])
		// start func returns here; execution proceeds to main func or exit trap
	}

	if entryIndex >= 0 {
		if entryIndex > maxInitIndex {
			maxInitIndex = entryIndex
		}

		sigIndex := m.Funcs[entryIndex]
		sig := m.Types[sigIndex]

		// TODO: move this out of codegen
		for i := range sig.Params {
			asm.PushImm(p, int64(entryArgs[i]))
		}

		opInitialCall(p, &p.FuncLinks[entryIndex])
		// main func returns here; execution proceeds to exit trap

		mainResultType = sig.Result
	}

	if mainResultType != wa.I32 {
		asm.ClearIntResultReg(p)
	}

	asm.Exit(p)

	if p.Text.Addr > int32(isa.CommonRODataAddr()) {
		panic("text is too long before common read-only data")
	}
	isa.AlignData(p, isa.CommonRODataAddr())

	roTableSize := len(m.TableFuncs) * 8
	commonROData := p.Text.Extend(rodata.TableOffset + roTableSize)
	binary.LittleEndian.PutUint32(commonROData[rodata.Mask7fOffset32:], 0x7fffffff)
	binary.LittleEndian.PutUint64(commonROData[rodata.Mask7fOffset64:], 0x7fffffffffffffff)
	binary.LittleEndian.PutUint32(commonROData[rodata.Mask80Offset32:], 0x80000000)
	binary.LittleEndian.PutUint64(commonROData[rodata.Mask80Offset64:], 0x8000000000000000)
	binary.LittleEndian.PutUint32(commonROData[rodata.Mask5f00Offset32:], 0x5f000000)
	binary.LittleEndian.PutUint64(commonROData[rodata.Mask43e0Offset64:], 0x43e0000000000000)

	for id := trap.MissingFunction + 1; id < trap.NumTraps; id++ {
		isa.AlignFunc(p)
		p.TrapLinks[id].Addr = p.Text.Addr
		asm.JumpToTrapHandler(p, id)
	}

	for i, imp := range m.ImportFuncs {
		addr := genImportTrampoline(p, m, i, imp)
		p.FuncLinks[i].Addr = addr
	}

	var midpoint int

	if eventHandler != nil {
		midpoint = maxInitIndex + 1
	} else {
		midpoint = len(m.Funcs)
	}

	for i := len(m.ImportFuncs); i < midpoint; i++ {
		genFunction(&funcStorage, load, i)
		isa.UpdateCalls(p.Text.Bytes(), &p.FuncLinks[i].L)
	}

	ptr := p.Text.Bytes()[isa.CommonRODataAddr()+rodata.TableOffset:]

	for i, funcIndex := range m.TableFuncs {
		var funcAddr uint32 // missing function trap by default

		if funcIndex < uint32(len(p.FuncLinks)) {
			ln := &p.FuncLinks[funcIndex]
			funcAddr = uint32(ln.Addr) // missing if not generated yet
			if funcAddr == 0 {
				ln.AddTableIndex(i)
			}
		}

		sigIndex := uint32(math.MaxInt32) // invalid signature index by default

		if funcIndex < uint32(len(m.Funcs)) {
			sigIndex = m.Funcs[funcIndex]
		}

		binary.LittleEndian.PutUint64(ptr[:8], (uint64(sigIndex)<<32)|uint64(funcAddr))
		ptr = ptr[8:]

		debug.Printf("element %d: function %d at 0x%x with signature %d", i, funcIndex, funcAddr, sigIndex)
	}

	if midpoint < len(m.Funcs) {
		eventHandler(event.Init)

		for i := midpoint; i < len(m.Funcs); i++ {
			genFunction(&funcStorage, load, i)
		}

		eventHandler(event.FunctionBarrier)

		roTable := p.Text.Bytes()[isa.CommonRODataAddr()+rodata.TableOffset:]

		for i := midpoint; i < len(m.Funcs); i++ {
			ln := &p.FuncLinks[i]
			addr := uint32(ln.Addr)

			for _, tableIndex := range ln.TableIndexes {
				offset := tableIndex * 8
				atomic.PutUint32(roTable[offset:offset+4], addr) // overwrite only function addr
			}

			isa.UpdateCalls(p.Text.Bytes(), &ln.L)
		}
	}
}

func opInitialCall(p *gen.Prog, l *link.FuncL) {
	retAddr := asm.CallMissing(p)
	p.Map.PutCallSite(retAddr, 0) // initial stack frame
	l.AddSite(retAddr)
}
