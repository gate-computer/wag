// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"testing"

	"gate.computer/wag/internal/obj"
)

func TestTrapMap(*testing.T) {
	var _ obj.DebugObjectMapper = new(TrapMap)
}

func TestInsnMap(*testing.T) {
	var _ obj.DebugObjectMapper = new(InsnMap)
}
