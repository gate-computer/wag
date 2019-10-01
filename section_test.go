// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/tsavola/wag/compile"
	"github.com/tsavola/wag/section"
)

func TestSection(t *testing.T) {
	var (
		sectionMap         = section.NewMap()
		nameSectionMapping = new(section.MappedNameSection)
		imaginaryMapping   = new(section.CustomMapping)
		loadConfig         = compile.Config{
			SectionMapper: sectionMap.Mapper(),
			CustomSectionLoader: section.CustomLoaders{
				section.CustomName: nameSectionMapping.Loader(sectionMap),
				"imaginary":        imaginaryMapping.Loader(sectionMap),
			}.Load,
		}
	)

	data, err := ioutil.ReadFile("testdata/hello.wasm")
	if err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(data)

	mod, err := compile.LoadInitialSections(&compile.ModuleConfig{Config: loadConfig}, r)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < mod.NumImportFuncs(); i++ {
		// Arbitrary (but existing) implementation.
		mod.SetImportFunc(i, uint32(lib.NumImportFuncs()))
	}

	err = compile.LoadCodeSection(&compile.CodeConfig{Config: loadConfig}, r, mod, lib)
	if err != nil {
		t.Fatal(err)
	}

	err = compile.LoadDataSection(&compile.DataConfig{Config: loadConfig}, r, mod)
	if err != nil {
		t.Fatal(err)
	}

	err = compile.LoadCustomSections(&loadConfig, r)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("section map: %#v", sectionMap.Sections)
	t.Logf("name section mapping: %#v", nameSectionMapping.Mapping)
	t.Logf("imaginary mapping: %#v", imaginaryMapping)
}
