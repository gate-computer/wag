// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/regalloc"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wasm"
)

type Module = module.Module

func offsetOfGlobal(m *Module, index uint32) int32 {
	return (int32(index) - int32(len(m.Globals))) * gen.WordSize
}

func GenProgram(m *Module, load loader.L, entryDefined bool, entrySymbol string, entryArgs []uint64, startTrigger chan<- struct{}, insnMap InsnMap) {
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

	m.FuncLinks = make([]links.FunctionL, len(m.FuncSigs))
	insnMap.Init(int(funcCodeCount))

	roTableSize := len(m.TableFuncs) * 8
	buf := m.ROData.ResizeBytes(gen.ROTableAddr + roTableSize)
	binary.LittleEndian.PutUint32(buf[gen.ROMask7fAddr32:], 0x7fffffff)
	binary.LittleEndian.PutUint64(buf[gen.ROMask7fAddr64:], 0x7fffffffffffffff)
	binary.LittleEndian.PutUint32(buf[gen.ROMask80Addr32:], 0x80000000)
	binary.LittleEndian.PutUint64(buf[gen.ROMask80Addr64:], 0x8000000000000000)
	binary.LittleEndian.PutUint32(buf[gen.ROMask5f00Addr32:], 0x5f000000)
	binary.LittleEndian.PutUint64(buf[gen.ROMask43e0Addr64:], 0x43e0000000000000)

	isa.OpEnterTrapHandler(m.Text, trap.MissingFunction) // at zero address

	isa.OpInit(m.Text)
	// after init, execution proceeds to start func, main func, or exit trap

	maxInitIndex := -1
	mainResultType := wasm.Void

	if m.StartDefined {
		maxInitIndex = int(m.StartIndex)

		opInitCall(m, &m.FuncLinks[m.StartIndex])
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
				reg := paramRegs.IterForward(gen.TypeRegCategory(t))
				isa.OpMoveIntImm(m.Text, reg, entryArgs[i])
			}
		}

		opInitCall(m, &m.FuncLinks[m.EntryIndex])
		// main func returns here; execution proceeds to exit trap

		mainResultType = sig.Result
	}

	if mainResultType != wasm.I32 {
		isa.OpClearIntResultReg(m.Text)
	}

	isa.OpEnterExitTrapHandler(m.Text)

	for id := trap.MissingFunction + 1; id < trap.NumTraps; id++ {
		m.TrapLinks[id].Addr = m.Text.Pos()
		isa.OpEnterTrapHandler(m.Text, id)
	}

	for i, imp := range m.ImportFuncs {
		addr := genImportEntry(m, imp)
		m.FuncLinks[i].Addr = addr
	}

	m.Regs.Init(isa.AvailRegs())

	var midpoint int

	if startTrigger != nil {
		midpoint = maxInitIndex + 1
	} else {
		midpoint = len(m.FuncSigs)
	}

	for i := len(m.ImportFuncs); i < midpoint; i++ {
		genFunction(&function{Module: m, insnMap: insnMap}, load, i)
		isa.UpdateCalls(m.Text.Bytes(), &m.FuncLinks[i].L)
	}

	ptr := m.ROData.Bytes()[gen.ROTableAddr:]

	for i, funcIndex := range m.TableFuncs {
		var funcAddr uint32 // missing function trap by default

		if funcIndex < uint32(len(m.FuncLinks)) {
			link := &m.FuncLinks[funcIndex]
			funcAddr = uint32(link.Addr) // missing if not generated yet
			if funcAddr == 0 {
				link.AddTableIndex(i)
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
			genFunction(&function{Module: m, insnMap: insnMap}, load, i)
		}

		isa.ClearInsnCache()

		roDataBuf := m.ROData.Bytes()

		for i := midpoint; i < len(m.FuncSigs); i++ {
			link := &m.FuncLinks[i]
			addr := uint32(link.Addr)

			for _, tableIndex := range link.TableIndexes {
				offset := gen.ROTableAddr + tableIndex*8
				isa.PutUint32(roDataBuf[offset:offset+4], addr) // overwrite only function addr
			}

			isa.UpdateCalls(m.Text.Bytes(), &link.L)
		}

		isa.ClearInsnCache()
	}
}

func opInitCall(m *Module, l *links.FunctionL) {
	retAddr := isa.OpInitCall(m.Text)
	mapCallAddr(m, retAddr, 0) // initial stack frame
	l.AddSite(retAddr)
}

func mapCallAddr(m *Module, retAddr, stackOffset int32) {
	if m.CallMap != nil {
		debugf("map call: retAddr=0x%x stackOffset=%d", retAddr, stackOffset)
		m.CallMap = append(m.CallMap, module.CallSite{
			ReturnAddr:  retAddr,
			StackOffset: stackOffset,
		})
	}
}

func genImportEntry(m *Module, imp module.ImportFunction) (addr int32) {
	if debug {
		debugf("import function")
		debugDepth++
	}

	isa.AlignFunction(m.Text)
	addr = m.Text.Pos()
	mapFunctionAddr(m, addr)

	sigIndex := m.FuncSigs[imp.FuncIndex]
	sig := m.Sigs[sigIndex]

	if imp.Variadic {
		var paramRegs regalloc.Iterator
		numStackParams := paramRegs.Init(isa.ParamRegs(), sig.Args)
		if numStackParams > 0 {
			panic("import function has stack parameters")
		}

		for i := range sig.Args {
			t := sig.Args[i]
			reg := paramRegs.IterForward(gen.TypeRegCategory(t))
			isa.OpStoreStackReg(m.Text, t, -(int32(i)+1)*gen.WordSize, reg)
		}
	}

	isa.OpEnterImportFunction(m.Text, imp.AbsAddr, imp.Variadic, len(sig.Args), int(sigIndex))

	if debug {
		debugDepth--
		debugf("imported function")
	}

	return
}

func mapFunctionAddr(m *Module, addr int32) {
	if m.FuncMap != nil {
		debugf("map function: addr=0x%x", addr)
		m.FuncMap = append(m.FuncMap, addr)
	}
}
