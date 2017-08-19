// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sectionids

const (
	Unknown = iota
	Type
	Import
	Function
	Table
	Memory
	Global
	Export
	Start
	Element
	Code
	Data

	NumSections
)
