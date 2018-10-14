// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"bytes"
	"io"

	"github.com/tsavola/wag/internal/errorpanic"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/reader"
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
func (ns *NameSection) Load(_ string, r reader.R) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	for ns.readSubsection(r) {
	}

	return
}

func (ns *NameSection) readSubsection(r reader.R) (read bool) {
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
		ns.ModuleName = string(content)

	case nameSubsectionFunctionNames, nameSubsectionLocalNames:
		loadContent := loader.L{R: bytes.NewReader(content)}

		for range loadContent.Count() {
			funcIndex := loadContent.Varuint32()
			for uint32(len(ns.FuncNames)) <= funcIndex {
				ns.FuncNames = append(ns.FuncNames, FuncName{}) // TODO: optimize
			}

			fn := &ns.FuncNames[funcIndex]

			switch id {
			case nameSubsectionFunctionNames:
				funcNameLen := loadContent.Varuint32()
				fn.FuncName = string(loadContent.Bytes(funcNameLen))

			case nameSubsectionLocalNames:
				for range loadContent.Count() {
					localIndex := loadContent.Varuint32()
					for uint32(len(fn.LocalNames)) <= localIndex {
						fn.LocalNames = append(fn.LocalNames, "") // TODO: optimize
					}

					localNameLen := loadContent.Varuint32()
					fn.LocalNames[localIndex] = string(loadContent.Bytes(localNameLen))
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
func (ns *MappedNameSection) Loader(sectionMap *Map) func(string, reader.R) error {
	return func(sectionName string, r reader.R) error {
		ns.Mapping = sectionMap.Sections[Custom] // The latest one.
		return ns.NameSection.Load(sectionName, r)
	}
}
