// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package abi

const (
	TextAddrNoFunction = 0x00 // NoFunction trap handler.
	TextAddrExit       = 0x10 // Exit routine.
	TextAddrResume     = 0x20 // Return from import function or trap handler.
	TextAddrEnter      = 0x30 // Call start and entry functions, and exit.
)
