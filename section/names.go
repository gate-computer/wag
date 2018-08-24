// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"bytes"
	"io"

	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/mod"
)

type subsectionId byte

const (
	subsectionModuleName subsectionId = iota
	subsectionFunctionNames
	subsectionLocalNames
)

type FuncName struct { // TODO: rename?
	FunName    string   // TODO: rename?
	LocalNames []string // TODO: map?
}

type NameSection struct {
	ModuleName string
	FuncNames  []FuncName // TODO: map? rename?
}

// Load "name" custom section.
func (ns *NameSection) Load(_ string, r mod.Reader) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	load := loader.L{Reader: r}

	for {
		idByte, err := load.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				panic(err)
			}
		}
		id := subsectionId(idByte)
		contentSize := load.Varuint32()
		content := load.Bytes(contentSize)

		switch id {
		case subsectionModuleName:
			ns.ModuleName = string(content)

		case subsectionFunctionNames, subsectionLocalNames:
			loadContent := loader.L{Reader: bytes.NewReader(content)}

			for range loadContent.Count() {
				funIndex := loadContent.Varuint32()
				for uint32(len(ns.FuncNames)) <= funIndex {
					ns.FuncNames = append(ns.FuncNames, FuncName{}) // TODO: optimize
				}

				fn := &ns.FuncNames[funIndex]

				switch id {
				case subsectionFunctionNames:
					funNameLen := loadContent.Varuint32()
					fn.FunName = string(loadContent.Bytes(funNameLen))

				case subsectionLocalNames:
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
	}

	return
}
