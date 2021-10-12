// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"

	"gate.computer/wag/compile/event"
	"gate.computer/wag/internal/code"
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/atomic"
	"gate.computer/wag/internal/gen/debug"
	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/gen/rodata"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/object/abi"
	"gate.computer/wag/trap"
)

func GenProgram(
	text code.Buffer,
	objMap obj.ObjectMapper,
	load loader.L,
	m *module.M,
	lib *module.Library,
	eventHandler func(event.Event),
	initFuncCount int,
	breakpoints map[uint32]gen.Breakpoint,
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

	userFuncCount := len(m.Funcs) - len(m.ImportFuncs)
	if n := load.Varuint32(); n != uint32(userFuncCount) {
		panic(module.Errorf("wrong number of function bodies: %d (should be: %d)", n, userFuncCount))
	}
	p.Map.InitObjectMap(len(m.ImportFuncs), userFuncCount)

	p.DebugMap, _ = objMap.(obj.DebugObjectMapper)
	p.Debugger = makeDebugger(breakpoints, load.R)

	if p.Text.Addr != abi.TextAddrNoFunction {
		panic(errors.New("unexpected initial text address"))
	}
	asm.TrapHandlerRewindNoFunction(p)

	if p.Text.Addr == abi.TextAddrNoFunction || p.Text.Addr > abi.TextAddrExit {
		panic("bad text address after NoFunction trap handler")
	}
	asm.PadUntil(p, abi.TextAddrExit)
	p.TrapLinks[trap.Exit].Addr = p.Text.Addr
	asm.Exit(p)

	if p.Text.Addr == abi.TextAddrExit || p.Text.Addr > abi.TextAddrResume {
		panic("bad text address after Exit trap handler")
	}
	asm.PadUntil(p, abi.TextAddrResume)
	asm.Resume(p)

	if p.Text.Addr <= abi.TextAddrResume || p.Text.Addr > abi.TextAddrEnter {
		panic("bad text address after resume routine")
	}
	asm.PadUntil(p, abi.TextAddrEnter)
	// Virtual return point for resuming a program which was suspended before
	// execution started.  This call site must be at index 0, and its address
	// must match the TextAddrEnter routine.
	p.Map.PutCallSite(uint32(p.Text.Addr), obj.Word*2) // Depth includes start and entry addresses.
	asm.Enter(p)

	if p.Text.Addr > rodata.CommonsAddr {
		panic("bad text address after init routines")
	}
	genCommons(p)

	for id := trap.NoFunction + 1; id < trap.NumTraps; id++ {
		asm.AlignFunc(p)
		p.TrapLinks[id].Addr = p.Text.Addr

		switch id {
		case trap.CallStackExhausted:
			asm.TrapHandlerRewindCallStackExhausted(p)

		default:
			asm.TrapHandler(p, id)
		}
	}

	for i := range p.TrapLinkRewindSuspended {
		asm.AlignFunc(p)
		p.TrapLinkRewindSuspended[i].Addr = p.Text.Addr
		asm.TrapHandlerRewindSuspended(p, i)
	}

	for i := range p.TrapLinkTruncOverflow {
		asm.AlignFunc(p)
		p.TrapLinkTruncOverflow[i].Addr = p.Text.Addr
		asm.TrapHandlerTruncOverflow(p, i)
	}

	p.ImportContext = lib // Generate import functions in library context.

	for i, imp := range m.ImportFuncs {
		code := bytes.NewReader(lib.CodeFuncs[imp.LibraryFunc-uint32(len(lib.ImportFuncs))])
		sig := lib.Types[lib.Funcs[imp.LibraryFunc]]

		// Reserve stack space for function restart address, duplicate function
		// arguments, and duplicate (dummy) link address.
		numExtra := 1 + len(sig.Params) + 1

		genFunction(&funcStorage, loader.L{R: code}, i, sig, numExtra, false)
	}

	p.ImportContext = nil

	if eventHandler == nil {
		initFuncCount = len(m.Funcs)
	}

	for i := len(m.ImportFuncs); i < initFuncCount; i++ {
		genFunction(&funcStorage, load, i, m.Types[m.Funcs[i]], 0, false)
		linker.UpdateCalls(p.Text.Bytes(), &p.FuncLinks[i].L)
	}

	ptr := p.Text.Bytes()[rodata.TableAddr:]

	for i, funcIndex := range m.TableFuncs {
		var funcAddr uint32 // NoFunction trap by default

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

		if debug.Enabled {
			debug.Printf("element %d: function %d at 0x%x with signature %d", i, funcIndex, funcAddr, sigIndex)
		}
	}

	if initFuncCount < len(m.Funcs) {
		eventHandler(event.Init)

		for i := initFuncCount; i < len(m.Funcs); i++ {
			genFunction(&funcStorage, load, i, m.Types[m.Funcs[i]], 0, true)
		}

		eventHandler(event.FunctionBarrier)

		table := p.Text.Bytes()[rodata.TableAddr:]

		for i := initFuncCount; i < len(m.Funcs); i++ {
			ln := &p.FuncLinks[i]
			addr := uint32(ln.Addr)

			for _, tableIndex := range ln.TableIndexes {
				offset := tableIndex * 8
				atomic.PutUint32(table[offset:offset+4], addr) // overwrite only function addr
			}

			linker.UpdateCalls(p.Text.Bytes(), &ln.L)
		}
	}
}

// genCommons except the contents of the table.
func genCommons(p *gen.Prog) {
	asm.PadUntil(p, rodata.CommonsAddr)

	var (
		tableSize   = len(p.Module.TableFuncs) * 8
		commonsEnd  = rodata.TableAddr + tableSize
		commonsSize = commonsEnd - rodata.CommonsAddr
	)

	p.Text.Extend(commonsSize)
	text := p.Text.Bytes()

	binary.LittleEndian.PutUint32(text[rodata.Mask7fAddr32:], 0x7fffffff)
	binary.LittleEndian.PutUint64(text[rodata.Mask7fAddr64:], 0x7fffffffffffffff)
	binary.LittleEndian.PutUint32(text[rodata.Mask80Addr32:], 0x80000000)
	binary.LittleEndian.PutUint64(text[rodata.Mask80Addr64:], 0x8000000000000000)
	binary.LittleEndian.PutUint32(text[rodata.Mask5f00Addr32:], 0x5f000000)
	binary.LittleEndian.PutUint64(text[rodata.Mask43e0Addr64:], 0x43e0000000000000)
}
