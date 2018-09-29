// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"

	"github.com/tsavola/wag/object/file/internal"
)

const (
	headersAddr = 0x100000000
	textAddr    = 0x200000000
	memoryAddr  = 0x300000000
	pageSize    = 4096
)

type File internal.File

// WriteTo writes the contents of an executable program.
func (f *File) WriteTo(w io.Writer) (n int64, err error) {
	var b bytes.Buffer
	f.writeTo(&b)
	m, err := w.Write(b.Bytes())
	n = int64(m)
	return
}

func (f *File) writeTo(b *bytes.Buffer) {
	var (
		phnum           = 5
		headersSize     = roundSize(64+56*phnum, pageSize)
		runtimePageAddr = f.RuntimeAddr &^ (pageSize - 1)
		runtimePadding  = int(f.RuntimeAddr - runtimePageAddr)
		runtimeSize     = roundSize(runtimePadding+len(f.Runtime), pageSize)
		runtimeOffset   = headersSize
		textSize        = roundSize(len(f.Text), pageSize)
		textOffset      = runtimeOffset + runtimeSize
		globalsSize     = roundSize(f.MemoryOffset, pageSize)
		globalsPadding  = globalsSize - f.MemoryOffset
		memorySize      = roundSize(len(f.GlobalsMemory)-f.MemoryOffset, pageSize)
		dataAddr        = memoryAddr - globalsSize
		dataOffset      = textOffset + textSize
		dataSize        = globalsSize + memorySize
	)

	// File header
	binary.Write(b, binary.LittleEndian, elf.Header64{
		Ident: [elf.EI_NIDENT]byte{
			0:              0x7f,
			1:              'E',
			2:              'L',
			3:              'F',
			elf.EI_CLASS:   byte(elf.ELFCLASS64),
			elf.EI_DATA:    byte(elf.ELFDATA2LSB),
			elf.EI_VERSION: 1,
		},
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elfMachine),
		Version:   1,
		Entry:     f.RuntimeAddr,
		Phoff:     64,
		Shoff:     0,
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     uint16(phnum),
		Shentsize: 64,
		Shnum:     0,
		Shstrndx:  0,
	})

	// Program header #0
	writeBinaryArray(b, []interface{}{
		uint32(elf.PT_PHDR),      // type
		uint32(elf.PF_R),         // flags
		uint64(64),               // offset
		uint64(headersAddr + 64), // vaddr
		uint64(headersAddr + 64), // paddr
		uint64(56),               // filesz
		uint64(56),               // memsz
		uint64(pageSize),         // align
	})

	// Program header #1: load headers
	writeBinaryArray(b, []interface{}{
		uint32(elf.PT_LOAD), // type
		uint32(elf.PF_R),    // flags
		uint64(0),           // offset
		uint64(headersAddr), // vaddr
		uint64(headersAddr), // paddr
		uint64(headersSize), // filesz
		uint64(headersSize), // memsz
		uint64(pageSize),    // align
	})

	// Program header #2: load runtime
	writeBinaryArray(b, []interface{}{
		uint32(elf.PT_LOAD),         // type
		uint32(elf.PF_R | elf.PF_X), // flags
		uint64(runtimeOffset),       // offset
		uint64(runtimePageAddr),     // vaddr
		uint64(runtimePageAddr),     // paddr
		uint64(runtimeSize),         // filesz
		uint64(runtimeSize),         // memsz
		uint64(pageSize),            // align
	})

	// Program header #3: load text
	writeBinaryArray(b, []interface{}{
		uint32(elf.PT_LOAD),         // type
		uint32(elf.PF_R | elf.PF_X), // flags
		uint64(textOffset),          // offset
		uint64(textAddr),            // vaddr
		uint64(textAddr),            // paddr
		uint64(textSize),            // filesz
		uint64(textSize),            // memsz
		uint64(pageSize),            // align
	})

	// Program header #4: load globals and linear memory data
	writeBinaryArray(b, []interface{}{
		uint32(elf.PT_LOAD),         // type
		uint32(elf.PF_R | elf.PF_W), // flags
		uint64(dataOffset),          // offset
		uint64(dataAddr),            // vaddr
		uint64(dataAddr),            // paddr
		uint64(dataSize),            // filesz
		uint64(dataSize),            // memsz
		uint64(pageSize),            // align
	})

	align(b, pageSize)

	// Runtime
	if b.Len() != runtimeOffset {
		panic(b.Len())
	}
	for i := 0; i < runtimePadding; i++ {
		b.WriteByte(0)
	}
	b.Write(f.Runtime)

	align(b, pageSize)

	// Text
	if b.Len() != textOffset {
		panic(b.Len())
	}
	b.Write(f.Text)

	align(b, pageSize)

	// Globals and linear memory
	if b.Len() != dataOffset {
		panic(b.Len())
	}
	for i := 0; i < globalsPadding; i++ {
		b.WriteByte(0)
	}
	b.Write(f.GlobalsMemory)

	align(b, pageSize)
}

func writeBinaryArray(b *bytes.Buffer, fields []interface{}) {
	for _, x := range fields {
		binary.Write(b, binary.LittleEndian, x)
	}
}

func align(b *bytes.Buffer, alignment int) {
	l := roundSize(b.Len(), alignment)
	for b.Len() < l {
		b.WriteByte(0)
	}
}

func roundSize(value, alignment int) int {
	return (value + alignment - 1) &^ (alignment - 1)
}
