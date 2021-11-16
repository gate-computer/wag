// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"testing"

	"gate.computer/wag/internal/gen/codegen"
)

func init() {
	codegen.UnsupportedOpBreakpoint = true
}

func TestMain(m *testing.M) {
	if err := generateSpecData(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}
