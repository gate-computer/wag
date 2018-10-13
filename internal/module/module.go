// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package module

import (
	"fmt"

	"github.com/tsavola/wag/wa"
)

const (
	MagicNumber = uint32(0x6d736100)
	Version     = uint32(1)
)

type Header struct {
	MagicNumber uint32
	Version     uint32
}

type SectionId byte

const (
	SectionCustom = SectionId(iota)
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
	NumMetaSections = SectionElement + 1
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

func (id SectionId) String() string {
	if int(id) < len(sectionNames) {
		return sectionNames[id]
	} else {
		return fmt.Sprintf("<id 0x%x>", byte(id))
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
	VecIndex int
	Variadic bool
}

type ResizableLimits struct {
	Initial int
	Maximum int
	Defined bool
}

type Global struct {
	Type    wa.Type
	Mutable bool
	Init    uint64
}

type M struct {
	Types             []wa.FuncType
	Funcs             []uint32
	ImportFuncs       []ImportFunc
	TableLimitValues  ResizableLimits
	MemoryLimitValues ResizableLimits
	Globals           []Global
	ImportGlobals     []Import
	EntryIndex        uint32
	EntryDefined      bool
	ExportFuncs       map[string]uint32
	StartIndex        uint32
	StartDefined      bool
	TableFuncs        []uint32
}
