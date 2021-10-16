// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"bufio"
	"bytes"
	"io"

	"gate.computer/wag/internal/errorpanic"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
)

const (
	maxFuncNames  = 1000000 // Industry standard.
	maxLocalNames = 50000   // Industry standard.
)

const CustomName = "name"

const (
	nameSubsectionModuleName byte = iota
	nameSubsectionFunctionNames
	nameSubsectionLocalNames
)

type FuncName struct {
	FuncName   string
	LocalNames []string
}

type NameSection struct {
	ModuleName string
	FuncNames  []FuncName
}

// Load "name" section.
func (ns *NameSection) Load(_ string, r Reader, length uint32) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	r = bufio.NewReader(&io.LimitedReader{R: r, N: int64(length)})

	for ns.readSubsection(r) {
	}

	return
}

func (ns *NameSection) readSubsection(r Reader) (read bool) {
	id, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return
		}
		panic(err)
	}

	load := loader.L{R: r}

	contentSize := load.Varuint32()
	content := load.Bytes(contentSize)

	switch id {
	case nameSubsectionModuleName:
		ns.ModuleName = loader.String(content, "name section: module name")

	case nameSubsectionFunctionNames, nameSubsectionLocalNames:
		loadContent := loader.L{R: bytes.NewReader(content)}

		for range loadContent.Span(maxFuncNames, "function name count") {
			funcIndex := loadContent.Varuint32()
			if funcIndex >= uint32(len(ns.FuncNames)) {
				if funcIndex >= maxFuncNames {
					panic(module.Errorf("function name index is too large: %d", funcIndex))
				}

				buf := make([]FuncName, funcIndex+1)
				copy(buf, ns.FuncNames)
				ns.FuncNames = buf
			}

			fn := &ns.FuncNames[funcIndex]

			switch id {
			case nameSubsectionFunctionNames:
				funcNameLen := loadContent.Varuint32()
				fn.FuncName = loadContent.String(funcNameLen, "name section: function name")

			case nameSubsectionLocalNames:
				count := loadContent.Varuint32()
				if count > maxLocalNames {
					panic(module.Errorf("local name count is too large: %d", count))
				}
				fn.LocalNames = make([]string, count)

				for range make([]struct{}, count) {
					localIndex := loadContent.Varuint32()
					if localIndex >= uint32(len(fn.LocalNames)) {
						if localIndex >= maxLocalNames {
							panic(module.Errorf("local name index is too large: %d", localIndex))
						}

						buf := make([]string, localIndex+1)
						copy(buf, fn.LocalNames)
						fn.LocalNames = buf
					}

					localNameLen := loadContent.Varuint32()
					fn.LocalNames[localIndex] = loadContent.String(localNameLen, "name section: local name")
				}
			}
		}
	}

	read = true
	return
}

type MappedNameSection struct {
	NameSection
	Mapping ByteRange
}

// Loader of "name" section.  Remembers position.
func (ns *MappedNameSection) Loader(sectionMap *Map) func(string, Reader, uint32) error {
	return func(sectionName string, r Reader, length uint32) error {
		ns.Mapping = sectionMap.Sections[Custom] // The latest one.
		return ns.NameSection.Load(sectionName, r, length)
	}
}
