// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"bufio"
	"bytes"
	"io"
	"math"

	"gate.computer/wag/internal"
	"gate.computer/wag/internal/count"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/pan"
	"gate.computer/wag/wa"
	"gate.computer/wag/wa/opcode"
)

// rootLib has a dummy function.
var rootLib = module.Library{
	Types: []wa.FuncType{
		{},
	},
	Funcs: []uint32{
		0,
	},
	CodeFuncs: [][]byte{
		{
			2, // Body size.
			0, // Locals group count.
			byte(opcode.End),
		},
	},
}

type Library struct {
	l module.Library
}

func (m *Module) AsLibrary() (lib Library, err error) {
	if internal.DontPanic() {
		defer func() { err = pan.Error(recover()) }()
	}

	lib = m.asLibrary()
	return
}

func (m *Module) asLibrary() Library {
	if len(m.m.Globals) > 0 {
		pan.Panic(module.Error("library contains globals"))
	}
	if len(m.m.ImportGlobals) > 0 {
		pan.Panic(module.Error("library imports globals"))
	}
	if len(m.m.TableFuncs) > 0 {
		pan.Panic(module.Error("library uses indirect function calls"))
	}

	libImports := make([]module.ImportIndex, len(m.m.ImportFuncs))
	for i, imp := range m.m.ImportFuncs {
		libImports[i] = module.ImportIndex{
			Import:      imp.Import,
			VectorIndex: math.MinInt32, // Outrageous value by default.
		}
	}

	// Copy all arrays in case the originals have excess capacity.
	return Library{module.Library{
		Types:       append([]wa.FuncType{}, m.m.Types...),
		Funcs:       append([]uint32{}, m.m.Funcs...),
		ImportFuncs: libImports,
		Memory:      m.m.Memory,
		ExportFuncs: m.m.ExportFuncs,
	}}
}

func (lib *Library) LoadSections(r Loader) (err error) {
	if internal.DontPanic() {
		defer func() { err = pan.Error(recover()) }()
	}

	lib.loadSections(loader.Get(r))
	return
}

func (lib *Library) loadSections(load *loader.L) {
	codeBuf := bytes.NewBuffer(nil)

	mapper := &libraryMap{
		reader: count.Reader{
			R: bufio.NewReader(io.TeeReader(load, codeBuf)),
		},
	}

	load = loader.New(&mapper.reader, load.Tell())

	modImports := make([]module.ImportFunc, len(lib.l.ImportFuncs))
	for i, imp := range lib.l.ImportFuncs {
		modImports[i] = module.ImportFunc{
			Import:      imp.Import,
			LibraryFunc: 0, // In rootLib.
		}
	}

	mod := Module{module.M{
		Types:       lib.l.Types,
		Funcs:       lib.l.Funcs,
		ImportFuncs: modImports,
		Memory:      lib.l.Memory,
	}}

	loadCodeSection(&CodeConfig{Mapper: mapper}, load, mod, &rootLib)

	codeBytes := append([]byte{}, codeBuf.Bytes()...) // Avoid excess capacity.
	lib.l.CodeFuncs = make([][]byte, len(mapper.offsets))
	for i, off := range mapper.offsets {
		lib.l.CodeFuncs[i] = codeBytes[off:]
	}

	data := new(DataConfig)
	pan.Check(LoadDataSection(data, load, mod))
	if len(data.GlobalsMemory.Bytes()) > 0 {
		pan.Panic(module.Error("library contains data"))
	}
}

// TODO: these methods are copied from Module - combine implementations?

func (lib *Library) NumImportFuncs() int {
	return len(lib.l.ImportFuncs)
}

func (lib *Library) ImportFunc(i int) (module, field string, sig wa.FuncType) {
	imp := lib.l.ImportFuncs[i]
	module = imp.Module
	field = imp.Field

	sigIndex := lib.l.Funcs[i]
	sig = lib.l.Types[sigIndex]
	return
}

func (lib *Library) SetImportFunc(i, vectorIndex int) {
	if vectorIndex >= 0 {
		panic(vectorIndex)
	}
	lib.l.ImportFuncs[i].VectorIndex = vectorIndex
}

func (lib *Library) ExportFunc(field string) (funcIndex uint32, sig wa.FuncType, found bool) {
	funcIndex, found = lib.l.ExportFuncs[field]
	if found {
		sigIndex := lib.l.Funcs[funcIndex]
		sig = lib.l.Types[sigIndex]
	}
	return
}

type libraryMap struct {
	reader  count.Reader
	imports int
	offsets []uint32
}

func (m *libraryMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	m.imports = numImportFuncs
}

func (m *libraryMap) PutFuncAddr(addr uint32) {
	if m.imports > 0 {
		m.imports--
	} else {
		m.offsets = append(m.offsets, m.reader.N)
	}
}

func (*libraryMap) PutCallSite(uint32, int32) {}
