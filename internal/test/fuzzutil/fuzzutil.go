// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuzzutil

import (
	"encoding/binary"
	"io"

	"gate.computer/wag/buffer"
	werrors "gate.computer/wag/errors"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/wa"
	errors "golang.org/x/xerrors"
)

const (
	maxTextSize = 16 * 1024 * 1024
	maxDataSize = 16 * 1024 * 1024
)

var errFuzzImport = module.Error("fuzzy import failure")

func NewTextBuffer() *buffer.Limited          { return buffer.NewLimited(nil, maxTextSize) }
func NewGlobalsMemoryBuffer() *buffer.Limited { return buffer.NewLimited(nil, maxDataSize) }

type Resolver struct {
	Lib interface {
		ExportFunc(string) (uint32, wa.FuncType, bool)
	}
}

func (r Resolver) ResolveFunc(module, field string, sig wa.FuncType) (index uint32, err error) {
	index, actualSig, fieldFound := r.Lib.ExportFunc(field)
	if module != "env" || !fieldFound || !sig.Equal(actualSig) {
		err = errFuzzImport
		return
	}

	return
}

func (Resolver) ResolveGlobal(module, field string, t wa.Type) (bits uint64, err error) {
	if len(module) != 0 || len(field) != int(t.Size()) {
		err = errFuzzImport
		return
	}

	if t.Size() == wa.Size32 {
		bits = uint64(binary.LittleEndian.Uint32([]byte(field)))
	} else {
		bits = binary.LittleEndian.Uint64([]byte(field))
	}
	return
}

func Result(err error) (result int, ok bool) {
	var emod werrors.ModuleError
	var eres werrors.ResourceLimit

	switch {
	case err == nil:
		result = 1
		ok = true

	case err == io.EOF, errors.Is(err, io.ErrClosedPipe), errors.Is(err, io.ErrUnexpectedEOF), errors.As(err, &emod), errors.As(err, &eres):
		result = 0
		ok = true

	case errors.Is(err, errFuzzImport):
		result = -1
		ok = true
	}

	return
}
