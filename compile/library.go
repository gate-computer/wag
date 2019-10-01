// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"bufio"
	"bytes"
	"io"
	"math"

	"github.com/tsavola/wag/internal/errorpanic"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/reader"
	"github.com/tsavola/wag/wa"
	"github.com/tsavola/wag/wa/opcode"
)

// rootLib has a dummy function.
var rootLib = module.Library{
	Types: []wa.FuncType{
		wa.FuncType{},
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

func (mod Module) AsLibrary() (lib Library, err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	lib = mod.asLibrary()
	return
}

func (mod Module) asLibrary() Library {
	if len(mod.m.Globals) > 0 {
		panic(module.Error("library contains globals"))
	}
	if len(mod.m.ImportGlobals) > 0 {
		panic(module.Error("library imports globals"))
	}
	if len(mod.m.TableFuncs) > 0 {
		panic(module.Error("library uses indirect function calls"))
	}

	libImports := make([]module.ImportIndex, len(mod.m.ImportFuncs))
	for i, imp := range mod.m.ImportFuncs {
		libImports[i] = module.ImportIndex{
			Import:      imp.Import,
			VectorIndex: math.MinInt32, // Outrageous value by default.
		}
	}

	// Copy all arrays in case the originals have excess capacity.
	return Library{module.Library{
		Types:       append([]wa.FuncType{}, mod.m.Types...),
		Funcs:       append([]uint32{}, mod.m.Funcs...),
		ImportFuncs: libImports,
		ExportFuncs: mod.m.ExportFuncs,
	}}
}

func (lib *Library) LoadSections(r Reader) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	lib.loadSections(r)
	return
}

func (lib *Library) loadSections(r Reader) {
	codeBuf := bytes.NewBuffer(nil)

	mapper := &libraryMap{
		reader: reader.PosReader{
			R: bufio.NewReader(io.TeeReader(r, codeBuf)),
		},
	}

	r = &mapper.reader

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
	}}

	loadCodeSection(&CodeConfig{Mapper: mapper}, r, mod, &rootLib)

	codeBytes := append([]byte{}, codeBuf.Bytes()...) // Avoid excess capacity.
	lib.l.CodeFuncs = make([][]byte, len(mapper.offsets))
	for i, off := range mapper.offsets {
		lib.l.CodeFuncs[i] = codeBytes[off:]
	}

	data := new(DataConfig)
	if err := LoadDataSection(data, r, mod); err != nil {
		panic(err)
	}
	if len(data.GlobalsMemory.Bytes()) > 0 {
		panic(module.Error("library contains data"))
	}
}

// TODO: these methods are copied from Module - combine implementations?

func (l Library) NumImportFuncs() int {
	return len(l.l.ImportFuncs)
}

func (l Library) ImportFunc(i int) (module, field string, sig wa.FuncType) {
	imp := l.l.ImportFuncs[i]
	module = imp.Module
	field = imp.Field

	sigIndex := l.l.Funcs[i]
	sig = l.l.Types[sigIndex]
	return
}

func (l *Library) SetImportFunc(i int, vectorIndex int) {
	if vectorIndex >= 0 {
		panic(vectorIndex)
	}
	l.l.ImportFuncs[i].VectorIndex = vectorIndex
}

func (l Library) ExportFunc(field string) (funcIndex uint32, sig wa.FuncType, found bool) {
	funcIndex, found = l.l.ExportFuncs[field]
	if found {
		sigIndex := l.l.Funcs[funcIndex]
		sig = l.l.Types[sigIndex]
	}
	return
}

func (l *Library) XXX_Internal() interface{} { return &l.l }

type libraryMap struct {
	reader  reader.PosReader
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
		m.offsets = append(m.offsets, m.reader.Pos)
	}
}

func (*libraryMap) PutCallSite(uint32, int32)  {}
func (*libraryMap) PutTrapSite(uint32, int32)  {}
func (*libraryMap) PutInsnAddr(uint32)         {}
func (*libraryMap) PutDataBlock(uint32, int32) {}
