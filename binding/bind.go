// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package binding contains import and export utilities.
package binding

import (
	"gate.computer/wag/compile"
	"gate.computer/wag/wa"
)

// Well-known indexes of the import vector.  Import function addresses precede
// VectorIndexMemoryAddr.
const (
	VectorIndexLastImport    = -5
	VectorIndexMemoryAddr    = -4
	VectorIndexCurrentMemory = -3
	VectorIndexGrowMemory    = -2
	VectorIndexTrapHandler   = -1
)

// ImportResolver maps symbols to library function indexes and constant values.
//
// ResolveFunc returns a non-negative library function index.
//
// ResolveGlobal returns a bit pattern the interpretation of which depends on
// the scalar type.
type ImportResolver interface {
	ResolveFunc(module, field string, sig wa.FuncType) (funcIndex uint32, err error)
	ResolveGlobal(module, field string, t wa.Type) (init uint64, err error)
}

func BindImports(mod *compile.Module, reso ImportResolver) (err error) {
	for i := 0; i < mod.NumImportFuncs(); i++ {
		index, err := reso.ResolveFunc(mod.ImportFunc(i))
		if err != nil {
			return err
		}

		mod.SetImportFunc(i, index)
	}

	for i := 0; i < mod.NumImportGlobals(); i++ {
		init, err := reso.ResolveGlobal(mod.ImportGlobal(i))
		if err != nil {
			return err
		}

		mod.SetImportGlobal(i, init)
	}

	return nil
}

// LibraryImportResolver maps symbols to vector indexes.
//
// ResolveFunc returns a negative vector index.  The vector is addressed from
// the end.  VectorIndexLastImport is the largest valid index which ResolveFunc
// can return.
type LibraryImportResolver interface {
	ResolveFunc(module, field string, sig wa.FuncType) (vectorIndex int, err error)
}

func BindLibraryImports(lib *compile.Library, reso LibraryImportResolver) (err error) {
	for i := 0; i < lib.NumImportFuncs(); i++ {
		index, err := reso.ResolveFunc(lib.ImportFunc(i))
		if err != nil {
			return err
		}

		lib.SetImportFunc(i, index)
	}

	return nil
}
