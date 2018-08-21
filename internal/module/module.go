// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package module

import (
	"fmt"
	"io"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regalloc"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wasm"
	"github.com/tsavola/wag/wasm/function"
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
	SectionUnknown = iota
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

type Reader interface {
	io.Reader
	io.ByteScanner
}

type TextBuffer interface {
	gen.Buffer
}

type DataBuffer interface {
	Bytes() []byte
	ResizeBytes(n int) []byte
}

type ImportFunction struct {
	FuncIndex int
	Variadic  bool
	AbsAddr   uint64
}

type ResizableLimits struct {
	Initial int
	Maximum int
	Defined bool
}

type Global struct {
	Type    wasm.Type
	Mutable bool
	Init    uint64
}

type CallSite struct {
	ReturnAddr  int32
	StackOffset int32
}

type Module struct {
	Sigs              []function.Type
	FuncSigs          []uint32
	ImportFuncs       []ImportFunction
	TableLimitValues  ResizableLimits
	MemoryLimitValues ResizableLimits
	Globals           []Global
	NumImportGlobals  int
	EntryIndex        uint32
	EntryDefined      bool
	StartIndex        uint32
	StartDefined      bool
	TableFuncs        []uint32

	Text       TextBuffer
	RODataAddr int32
	ROData     DataBuffer
	TrapLinks  [trap.NumTraps]links.L
	FuncLinks  []links.FunctionL
	FuncMap    []int32
	CallMap    []CallSite
	Regs       regalloc.Allocator

	Data         DataBuffer
	MemoryOffset int
}
