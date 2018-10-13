// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package section contains binary stream manipulation utilities.
package section

import (
	"github.com/tsavola/wag/internal/module"
)

type Id = module.SectionId

const (
	Custom   = module.SectionCustom
	Type     = module.SectionType
	Import   = module.SectionImport
	Function = module.SectionFunction
	Table    = module.SectionTable
	Memory   = module.SectionMemory
	Global   = module.SectionGlobal
	Export   = module.SectionExport
	Start    = module.SectionStart
	Element  = module.SectionElement
	Code     = module.SectionCode
	Data     = module.SectionData
)
