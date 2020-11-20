// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package section contains binary stream manipulation utilities.
package section

import (
	"gate.computer/wag/internal/module"
)

type ID = module.SectionID

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
