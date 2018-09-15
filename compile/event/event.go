// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package event

// Event handler is invoked from a single goroutine (per compilation).
type Event int

const (
	// The init routine can be executed now.  It may cause MissingFunction
	// traps.
	//
	// This event is not necessarily delivered.
	Init = Event(iota)

	// All functions have been generated, but links to them haven't yet been
	// updated in previous functions.
	//
	// If required by ISA, code cache should be invalidated before the event
	// handler returns.
	//
	// This event is not necessarily delivered.
	FunctionBarrier
)

func (e Event) String() string {
	switch e {
	case Init:
		return "Init"

	case FunctionBarrier:
		return "FunctionBarrier"

	default:
		return "<invalid>"
	}
}
