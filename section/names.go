// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"errors"
	"math"

	"gate.computer/wag/internal"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"import.name/pan"
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
	if internal.DontPanic() {
		defer func() { err = internal.Error(recover()) }()
	}

	load, ok := r.(*loader.L)
	if !ok {
		// Use bogus offsets to avoid possible confusion.
		load = loader.New(r, math.MaxUint32)
	}

	for begin := load.Tell(); ; {
		switch pos := load.Tell() - begin; {
		case pos == int64(length):
			return

		case pos > int64(length):
			pan.Panic(errors.New("name section content exceeded payload length"))

		default:
			ns.readSubsection(load)
		}
	}
}

func (ns *NameSection) readSubsection(load *loader.L) {
	id := load.Byte()
	contentSize := load.Varuint32()

	switch id {
	case nameSubsectionModuleName:
		ns.ModuleName = load.String(contentSize, "name section: module name")

	case nameSubsectionFunctionNames, nameSubsectionLocalNames:
		for range load.Span(maxFuncNames, "function name count") {
			funcIndex := load.Varuint32()
			if funcIndex >= uint32(len(ns.FuncNames)) {
				if funcIndex >= maxFuncNames {
					pan.Panic(module.Errorf("function name index is too large: %d", funcIndex))
				}

				buf := make([]FuncName, funcIndex+1)
				copy(buf, ns.FuncNames)
				ns.FuncNames = buf
			}

			fn := &ns.FuncNames[funcIndex]

			switch id {
			case nameSubsectionFunctionNames:
				funcNameLen := load.Varuint32()
				fn.FuncName = load.String(funcNameLen, "name section: function name")

			case nameSubsectionLocalNames:
				count := load.Varuint32()
				if count > maxLocalNames {
					pan.Panic(module.Errorf("local name count is too large: %d", count))
				}
				fn.LocalNames = make([]string, count)

				for range make([]struct{}, count) {
					localIndex := load.Varuint32()
					if localIndex >= uint32(len(fn.LocalNames)) {
						if localIndex >= maxLocalNames {
							pan.Panic(module.Errorf("local name index is too large: %d", localIndex))
						}

						buf := make([]string, localIndex+1)
						copy(buf, fn.LocalNames)
						fn.LocalNames = buf
					}

					localNameLen := load.Varuint32()
					fn.LocalNames[localIndex] = load.String(localNameLen, "name section: local name")
				}
			}
		}

	default:
		load.Discard(contentSize)
	}
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
