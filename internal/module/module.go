// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package module

import (
	"fmt"

	"gate.computer/wag/wa"
)

const (
	MagicNumber = uint32(0x6d736100)
	Version     = uint32(1)
)

type Header struct {
	MagicNumber uint32
	Version     uint32
}

const (
	MaxFunctions  = 32768
	MaxFuncParams = 255
	MaxTypes      = MaxFunctions
	MaxImports    = MaxFunctions
)

type SectionID byte

const (
	SectionCustom = SectionID(iota)
	SectionType
	SectionImport
	SectionFunction
	SectionTable
	SectionMemory
	SectionGlobal
	SectionExport
	SectionStart
	SectionElement
	SectionCode
	SectionData

	NumSections
)

var sectionNames = []string{
	SectionCustom:   "custom",
	SectionType:     "type",
	SectionImport:   "import",
	SectionFunction: "function",
	SectionTable:    "table",
	SectionMemory:   "memory",
	SectionGlobal:   "global",
	SectionExport:   "export",
	SectionStart:    "start",
	SectionElement:  "element",
	SectionCode:     "code",
	SectionData:     "data",
}

func (id SectionID) String() string {
	if int(id) < len(sectionNames) {
		return sectionNames[id]
	} else {
		return fmt.Sprintf("<id %d>", byte(id))
	}
}

type ExternalKind byte

const (
	ExternalKindFunction = ExternalKind(iota)
	ExternalKindTable
	ExternalKindMemory
	ExternalKindGlobal
)

var externalKindStrings = []string{
	ExternalKindFunction: "function",
	ExternalKindTable:    "table",
	ExternalKindMemory:   "memory",
	ExternalKindGlobal:   "global",
}

func (kind ExternalKind) String() (s string) {
	if int(kind) < len(externalKindStrings) {
		s = externalKindStrings[kind]
	} else {
		s = fmt.Sprintf("<unknown external kind 0x%x>", byte(kind))
	}
	return
}

type Import struct {
	Module string
	Field  string
}

type ImportFunc struct {
	Import
	LibraryFunc uint32
}

type ResizableLimits struct {
	Init int
	Max  int // -1 if unlimited (memory).
}

type Global struct {
	Type       wa.Type
	Mutable    bool
	InitImport int8 // -1 if InitConst is defined.
	InitConst  uint64
}

type M struct {
	Types          []wa.FuncType
	Funcs          []uint32
	ImportFuncs    []ImportFunc
	Table          bool
	TableLimit     ResizableLimits
	Memory         bool
	MemoryLimit    ResizableLimits
	Globals        []Global
	ImportGlobals  []Import
	ExportFuncs    map[string]uint32
	StartIndex     uint32
	StartDefined   bool
	TableFuncs     []uint32
	CanonicalTypes map[uint32]uint32 // Includes only remapped indexes.
}

func (m *M) NumTable() uint32 {
	if m.Table {
		return 1
	}
	return 0
}

func (m *M) NumMemory() uint32 {
	if m.Memory {
		return 1
	}
	return 0
}

func (m *M) EvaluateGlobalInitializer(index int, value uint64) uint64 {
	if index == -1 {
		return value
	}

	// If the global value has not been initialized, index will be invalid, and
	// this will panic (on purpose).
	return m.Globals[index].InitConst
}

func (m *M) GetCanonicalTypeIndex(index uint32) uint32 {
	if i, found := m.CanonicalTypes[index]; found {
		return i
	}
	return index
}

type ImportIndex struct {
	Import
	VectorIndex int
}

type Library struct {
	Types       []wa.FuncType
	Funcs       []uint32
	ImportFuncs []ImportIndex
	Memory      bool
	ExportFuncs map[string]uint32
	CodeFuncs   [][]byte
}
