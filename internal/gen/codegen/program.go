// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/regalloc"
	"github.com/tsavola/wag/internal/link"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/rodata"
	"github.com/tsavola/wag/trap"
)

func GenProgram(m *module.M, load loader.L, entrySymbol string, entryArgs []uint64, startTrigger chan<- struct{}) {
	p := &gen.Prog{
		FuncLinks: make([]link.FuncL, len(m.FuncSigs)),
	}

	if debug {
		if debugDepth != 0 {
			debugf("")
		}
		debugDepth = 0
	}

	funcCodeCount := load.Varuint32()
	if needed := len(m.FuncSigs) - len(m.ImportFuncs); funcCodeCount != uint32(needed) {
		panic(fmt.Errorf("wrong number of function bodies: %d (should be: %d)", funcCodeCount, needed))
	}

	m.Map.InitObjectMap(len(m.ImportFuncs), int(funcCodeCount))

	roTableSize := len(m.TableFuncs) * 8
	buf := m.ROData.ResizeBytes(rodata.TableAddr + roTableSize)
	binary.LittleEndian.PutUint32(buf[rodata.Mask7fAddr32:], 0x7fffffff)
	binary.LittleEndian.PutUint64(buf[rodata.Mask7fAddr64:], 0x7fffffffffffffff)
	binary.LittleEndian.PutUint32(buf[rodata.Mask80Addr32:], 0x80000000)
	binary.LittleEndian.PutUint64(buf[rodata.Mask80Addr64:], 0x8000000000000000)
	binary.LittleEndian.PutUint32(buf[rodata.Mask5f00Addr32:], 0x5f000000)
	binary.LittleEndian.PutUint64(buf[rodata.Mask43e0Addr64:], 0x43e0000000000000)

	isa.OpEnterTrapHandler(m, trap.MissingFunction) // at zero address

	isa.OpInit(m)
	// after init, execution proceeds to start func, main func, or exit trap

	maxInitIndex := -1
	mainResultType := abi.Void

	if m.StartDefined {
		maxInitIndex = int(m.StartIndex)

		opInitCall(m, &p.FuncLinks[m.StartIndex])
		// start func returns here; execution proceeds to main func or exit trap
	}

	if m.EntryDefined {
		if index := int(m.EntryIndex); index > maxInitIndex {
			maxInitIndex = index
		}

		sigIndex := m.FuncSigs[m.EntryIndex]
		sig := m.Sigs[sigIndex]

		{
			var paramRegs regalloc.Iterator
			paramRegs.Init(isa.ParamRegs(), sig.Args)

			for i, t := range sig.Args {
				reg := paramRegs.IterForward(t.Category())
				isa.OpMoveIntImm(m, reg, entryArgs[i])
			}
		}

		opInitCall(m, &p.FuncLinks[m.EntryIndex])
		// main func returns here; execution proceeds to exit trap

		mainResultType = sig.Result
	}

	if mainResultType != abi.I32 {
		isa.OpClearIntResultReg(m)
	}

	isa.OpEnterExitTrapHandler(m)

	for id := trap.MissingFunction + 1; id < trap.NumTraps; id++ {
		p.TrapLinks[id].Addr = m.Text.Addr
		isa.OpEnterTrapHandler(m, id)
	}

	for i, imp := range m.ImportFuncs {
		addr := genImportEntry(m, imp)
		p.FuncLinks[i].Addr = addr
	}

	var midpoint int

	if startTrigger != nil {
		midpoint = maxInitIndex + 1
	} else {
		midpoint = len(m.FuncSigs)
	}

	for i := len(m.ImportFuncs); i < midpoint; i++ {
		genFunction(m, p, load, i)
		isa.UpdateCalls(m.Text.Bytes(), &p.FuncLinks[i].L)
	}

	ptr := m.ROData.Bytes()[rodata.TableAddr:]

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

		debugf("element %d: function %d at 0x%x with signature %d", i, funcIndex, funcAddr, sigIndex)
	}

	if startTrigger != nil {
		close(startTrigger)
	}

	if midpoint < len(m.FuncSigs) {
		for i := midpoint; i < len(m.FuncSigs); i++ {
			genFunction(m, p, load, i)
		}

		isa.ClearInsnCache()

		roDataBuf := m.ROData.Bytes()

		for i := midpoint; i < len(m.FuncSigs); i++ {
			ln := &p.FuncLinks[i]
			addr := uint32(ln.Addr)

			for _, tableIndex := range ln.TableIndexes {
				offset := rodata.TableAddr + tableIndex*8
				isa.PutUint32(roDataBuf[offset:offset+4], addr) // overwrite only function addr
			}

			isa.UpdateCalls(m.Text.Bytes(), &ln.L)
		}

		isa.ClearInsnCache()
	}
}

func opInitCall(m *module.M, l *link.FuncL) {
	retAddr := isa.OpInitCall(m)
	m.Map.PutCallSite(retAddr, 0) // initial stack frame
	l.AddSite(retAddr)
}
