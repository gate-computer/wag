// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sections

import (
	"bytes"
	"io"

	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/reader"
)

type subsectionId byte

const (
	subsectionModuleName subsectionId = iota
	subsectionFunctionNames
	subsectionLocalNames
)

type FunctionName struct { // TODO: rename?
	FunName    string   // TODO: rename?
	LocalNames []string // TODO: map?
}

type NameSection struct {
	ModuleName    string
	FunctionNames []FunctionName // TODO: map? rename?
}

// Load "name" custom section.
func (ns *NameSection) Load(_ string, r reader.Reader) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	load := loader.L{r}

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
			loadContent := loader.L{bytes.NewReader(content)}

			for range loadContent.Count() {
				funIndex := loadContent.Varuint32()
				for uint32(len(ns.FunctionNames)) <= funIndex {
					ns.FunctionNames = append(ns.FunctionNames, FunctionName{}) // TODO: optimize
				}

				fn := &ns.FunctionNames[funIndex]

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
