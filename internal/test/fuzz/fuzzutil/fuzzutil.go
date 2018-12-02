// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuzzutil

import (
	"hash/crc32"
	"hash/crc64"
	"io"
	"math"

	"github.com/tsavola/wag/binding"
	"github.com/tsavola/wag/buffer"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/wa"
)

const (
	maxTextSize = 16 * 1024 * 1024
	maxDataSize = 16 * 1024 * 1024
)

var errFuzzImport = module.Error("fuzzy import failure")
var crc64Table = crc64.MakeTable(crc64.ISO)

func NewTextBuffer() *buffer.Limited          { return buffer.NewLimited(nil, maxTextSize) }
func NewGlobalsMemoryBuffer() *buffer.Limited { return buffer.NewLimited(nil, maxDataSize) }

var Resolver resolver

type resolver struct{}

func (resolver) ResolveFunc(module, field string, sig wa.FuncType) (index int, err error) {
	h := crc32.NewIEEE()
	h.Write([]byte(module))
	h.Write([]byte(field))
	index = -int((uint64(h.Sum32()) * 8) / 7)
	if index > binding.VectorIndexLastImportFunc || index < math.MinInt32 {
		err = errFuzzImport
	}
	return
}

func (resolver) ResolveGlobal(module, field string, t wa.Type) (value uint64, err error) {
	h := crc64.New(crc64Table)
	h.Write([]byte(module))
	h.Write([]byte(field))
	value = h.Sum64()
	if value%7 == 0 {
		err = errFuzzImport
	}
	return
}

func IsFine(err error) bool {
	switch err {
	case io.EOF, io.ErrClosedPipe, io.ErrUnexpectedEOF:
		return true
	}

	switch err.(type) {
	case interface{ ModuleError() string }:
		return true
	}

	return false
}
