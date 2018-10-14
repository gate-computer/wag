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
)

func GenProgram(
	text code.Buffer,
	objMap obj.ObjectMapper,
	load loader.L,
	m *module.M,
	eventHandler func(event.Event),
	initFuncCount int,
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

	if p.Text.Addr != 0 {
		panic("initial text address is non-zero")
	}
	asm.JumpToTrapHandler(p, trap.MissingFunction)

	if p.Text.Addr == 0 || p.Text.Addr > obj.TextAddrResume {
		panic("bad text address after MissingFunction trap handler")
	}
	isa.AlignFunc(p)
	asm.Resume(p)

	if p.Text.Addr <= obj.TextAddrResume || p.Text.Addr > obj.TextAddrInitStart {
		panic("bad text address after resume routine")
	}
	isa.AlignFunc(p)
	asm.Init(p)

	if m.StartDefined {
		if int(m.StartIndex) >= initFuncCount {
			initFuncCount = int(m.StartIndex) + 1
		}
		retAddr := asm.CallMissing(p)
		p.Map.PutCallSite(retAddr, obj.Word*2) // stack depth excluding entry args (including link addr)
		p.FuncLinks[m.StartIndex].AddSite(retAddr)
	}

	if p.Text.Addr <= obj.TextAddrInitStart || p.Text.Addr > obj.TextAddrInitEntry {
		panic("bad text address after init routine and start function call")
	}
	retAddr := asm.InitCallEntry(p)
	p.Map.PutCallSite(retAddr, obj.Word) // stack depth excluding entry args (including link addr)

	if p.Text.Addr > rodata.CommonsAddr {
		panic("bad text address after init routines")
	}
	genCommons(p)

	for id := trap.MissingFunction + 1; id < trap.NumTraps; id++ {
		isa.AlignFunc(p)
		p.TrapLinks[id].Addr = p.Text.Addr
		asm.JumpToTrapHandler(p, id)
	}

	for i, imp := range m.ImportFuncs {
		addr := genImportTrampoline(p, m, i, imp)
		p.FuncLinks[i].Addr = addr
	}

	if eventHandler == nil {
		initFuncCount = len(m.Funcs)
	}

	for i := len(m.ImportFuncs); i < initFuncCount; i++ {
		genFunction(&funcStorage, load, i)
		isa.UpdateCalls(p.Text.Bytes(), &p.FuncLinks[i].L)
	}

	ptr := p.Text.Bytes()[rodata.TableAddr:]

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

	if initFuncCount < len(m.Funcs) {
		eventHandler(event.Init)

		for i := initFuncCount; i < len(m.Funcs); i++ {
			genFunction(&funcStorage, load, i)
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

			isa.UpdateCalls(p.Text.Bytes(), &ln.L)
		}
	}
}

// genCommons except the contents of the table.
func genCommons(p *gen.Prog) {
	isa.PadUntil(p, rodata.CommonsAddr)

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
