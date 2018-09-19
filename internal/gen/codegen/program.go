// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/data"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/atomic"
	"github.com/tsavola/wag/internal/gen/debug"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/trap"
)

// alignType rounds up.
func alignType(addr int, t abi.Type) int {
	mask := int(t.Size()) - 1
	return (addr + mask) &^ mask
}

func GenProgram(
	text code.Buffer,
	roData data.Buffer,
	roDataAddr int32,
	objMap obj.Map,
	load loader.L,
	m *module.M,
	entrySymbol string,
	entryArgs []uint64,
	eventHandler func(event.Event),
) {
	p := &gen.Prog{
		Text:       code.Buf{Buffer: text},
		ROData:     roData,
		RODataAddr: roDataAddr,
		Map:        objMap,

		FuncLinks: make([]link.FuncL, len(m.FuncSigs)),
	}

	if debug.Enabled {
		if debug.Depth != 0 {
			debug.Printf("")
		}
		debug.Depth = 0
	}

	funcCodeCount := load.Varuint32()
	if needed := len(m.FuncSigs) - len(m.ImportFuncs); funcCodeCount != uint32(needed) {
		panic(fmt.Errorf("wrong number of function bodies: %d (should be: %d)", funcCodeCount, needed))
	}

	p.Map.InitObjectMap(len(m.ImportFuncs), int(funcCodeCount))

	roTableSize := len(m.TableFuncs) * 8
	buf := p.ROData.ResizeBytes(rodata.TableAddr + roTableSize)
	binary.LittleEndian.PutUint32(buf[rodata.Mask7fAddr32:], 0x7fffffff)
	binary.LittleEndian.PutUint64(buf[rodata.Mask7fAddr64:], 0x7fffffffffffffff)
	binary.LittleEndian.PutUint32(buf[rodata.Mask80Addr32:], 0x80000000)
	binary.LittleEndian.PutUint64(buf[rodata.Mask80Addr64:], 0x8000000000000000)
	binary.LittleEndian.PutUint32(buf[rodata.Mask5f00Addr32:], 0x5f000000)
	binary.LittleEndian.PutUint64(buf[rodata.Mask43e0Addr64:], 0x43e0000000000000)

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
	mainResultType := abi.Void

	if m.StartDefined {
		maxInitIndex = int(m.StartIndex)

		opInitialCall(p, &p.FuncLinks[m.StartIndex])
		// start func returns here; execution proceeds to main func or exit trap
	}

	if m.EntryDefined {
		if index := int(m.EntryIndex); index > maxInitIndex {
			maxInitIndex = index
		}

		sigIndex := m.FuncSigs[m.EntryIndex]
		sig := m.Sigs[sigIndex]

		for i := range sig.Args {
			asm.PushImm(p, int64(entryArgs[i]))
		}

		opInitialCall(p, &p.FuncLinks[m.EntryIndex])
		// main func returns here; execution proceeds to exit trap

		mainResultType = sig.Result
	}

	if mainResultType != abi.I32 {
		asm.ClearIntResultReg(p)
	}

	asm.Exit(p)

	for id := trap.MissingFunction + 1; id < trap.NumTraps; id++ {
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
		midpoint = len(m.FuncSigs)
	}

	for i := len(m.ImportFuncs); i < midpoint; i++ {
		genFunction(p, load, m, i)
		isa.UpdateCalls(p.Text.Bytes(), &p.FuncLinks[i].L)
	}

	ptr := p.ROData.Bytes()[rodata.TableAddr:]

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

		if funcIndex < uint32(len(m.FuncSigs)) {
			sigIndex = m.FuncSigs[funcIndex]
		}

		binary.LittleEndian.PutUint64(ptr[:8], (uint64(sigIndex)<<32)|uint64(funcAddr))
		ptr = ptr[8:]

		debug.Printf("element %d: function %d at 0x%x with signature %d", i, funcIndex, funcAddr, sigIndex)
	}

	if midpoint < len(m.FuncSigs) {
		eventHandler(event.Init)

		for i := midpoint; i < len(m.FuncSigs); i++ {
			genFunction(p, load, m, i)
		}

		eventHandler(event.FunctionBarrier)

		roDataBuf := p.ROData.Bytes()

		for i := midpoint; i < len(m.FuncSigs); i++ {
			ln := &p.FuncLinks[i]
			addr := uint32(ln.Addr)

			for _, tableIndex := range ln.TableIndexes {
				offset := rodata.TableAddr + tableIndex*8
				atomic.PutUint32(roDataBuf[offset:offset+4], addr) // overwrite only function addr
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
