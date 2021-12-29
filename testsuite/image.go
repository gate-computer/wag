// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"gate.computer/gate/image"
	"gate.computer/wag/binary"
	"gate.computer/wag/binding"
	"gate.computer/wag/compile"
	"gate.computer/wag/internal/test/library"
	"gate.computer/wag/object"
	"gate.computer/wag/object/debug/dump"
	"gate.computer/wag/section"
)

const (
	maxTextSize   = 1048576
	stackSize     = 16384
	maxMemorySize = 52756480
	maxExports    = 479
)

var lib = *library.Load("testdata/library.wasm", false, func(r binary.Reader) library.L {
	mod, err := compile.LoadInitialSections(nil, r)
	if err != nil {
		panic(err)
	}

	lib, err := mod.AsLibrary()
	if err != nil {
		panic(err)
	}

	if err := binding.BindLibraryImports(&lib, libResolver{}); err != nil {
		panic(err)
	}

	return &lib
}).(*compile.Library)

type expected struct {
	moduleError func(error) bool
	codeError   func(error) bool
	dataError   func(error) bool
	customError func(error) bool
}

type program struct {
	mod     compile.Module
	funcs   object.FuncMap
	image   *image.Program
	globals []byte
}

// buildProgram returns nil on error.
func buildProgram(t *testing.T, filename string, wasm []byte, expect *expected) *program {
	if expect == nil {
		expect = new(expected)
	}

	t.Log("filename:", filename)

	r := bytes.NewReader(wasm)

	nameSection := new(section.NameSection)
	config := compile.Config{
		CustomSectionLoader: section.CustomLoader(map[string]section.CustomContentLoader{
			section.CustomName: nameSection.Load,
		}),
	}
	moduleConfig := &compile.ModuleConfig{
		Config:     config,
		MaxExports: maxExports,
	}

	m, err := compile.LoadInitialSections(moduleConfig, r)
	if err != nil {
		if expect.moduleError == nil || !expect.moduleError(err) {
			t.Error(err)
		}
		return nil
	}

	if err := binding.BindImports(&m, modResolver{L: lib}); err != nil {
		t.Error(err)
		return nil
	}

	objectMap := new(object.CallMap)

	b, err := image.NewBuild(image.Memory, 0, maxTextSize, objectMap, false)
	if err != nil {
		t.Error(err)
		return nil
	}
	defer func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	}()

	codeConfig := &compile.CodeConfig{
		Text:   b.TextBuffer(),
		Mapper: objectMap,
		Config: config,
	}

	if err := compile.LoadCodeSection(codeConfig, r, m, lib); err != nil {
		if expect.codeError == nil || !expect.codeError(err) {
			t.Error(err)
		}
		return nil
	}

	var textDump []byte
	if testing.Verbose() && os.Getenv("WAG_TEST_DUMP_TEXT") == path.Base(filename) {
		textDump = append([]byte(nil), b.TextBuffer().Bytes()...)
	}

	if err := b.FinishText(stackSize, 0, m.GlobalsSize(), m.InitialMemorySize()); err != nil {
		t.Error(err)
		return nil
	}

	dataConfig := &compile.DataConfig{
		GlobalsMemory:   b.GlobalsMemoryBuffer(),
		MemoryAlignment: b.MemoryAlignment(),
		Config:          config,
	}

	if err := compile.LoadDataSection(dataConfig, r, m); err != nil {
		if expect.dataError == nil || !expect.dataError(err) {
			t.Error(err)
		}
		return nil
	}

	var globals []byte
	if size := m.GlobalsSize(); size > 0 {
		align := b.MemoryAlignment()
		globals = append([]byte(nil), b.GlobalsMemoryBuffer().Bytes()[:align][align-size:]...)
	}

	if err := compile.LoadCustomSections(&config, r); err != nil {
		if expect.customError == nil || !expect.customError(err) {
			t.Error(err)
		}
		return nil
	}

	if textDump != nil {
		if err := dump.Text(os.Stdout, textDump, 0, objectMap.FuncAddrs, nameSection); err != nil {
			t.Error(err)
		}
	}

	startIndex := -1
	if i, defined := m.StartFunc(); defined {
		startIndex = int(i)
	}

	p, err := b.FinishProgram(image.SectionMap{}, m, startIndex, true, nil, 0)
	if err != nil {
		t.Error(err)
		return nil
	}

	return &program{m, objectMap.FuncMap, p, globals}
}

func (p *program) close(t *testing.T) {
	if err := p.image.Close(); err != nil {
		t.Error(err)
	}
}

func newInstance(t *testing.T, p *program, entry string) *image.Instance {
	entryIndex := -1

	if entry != "" {
		i, sig, found := p.mod.ExportFunc(entry)
		if !found {
			t.Error(entry)
			return nil
		}
		if !binding.IsEntryFuncType(sig) {
			t.Error(sig)
			return nil
		}
		entryIndex = int(i)

		t.Log("entry index:", entryIndex)
	}

	inst, err := image.NewInstance(p.image, maxMemorySize, stackSize, entryIndex)
	if err != nil {
		t.Error(err)
		return nil
	}

	return inst
}

func readTestData(t *testing.T, filename string) []byte {
	data, err := ioutil.ReadFile(path.Join("testdata", filename))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
