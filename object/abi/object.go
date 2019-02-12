// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package abi

type Routine uint32

const (
	TextAddrNoFunction = Routine(0x00) // NoFunction trap handler.
	TextAddrResume     = Routine(0x10) // Return from import function or trap handler.
	TextAddrStart      = Routine(0x20) // Call start and entry functions, and exit.
	TextAddrEnter      = Routine(0x30) // Call entry function and exit.
)
