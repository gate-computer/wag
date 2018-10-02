// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package binding

import (
	"fmt"

	"github.com/tsavola/wag/compile"
	"github.com/tsavola/wag/wa"
)

// GetMainFunc, the result type of which is void or i32.  Parameter count or
// types are not checked.
func GetMainFunc(mod *compile.Module, name string) (funcIndex uint32, sig wa.FuncType, err error) {
	funcIndex, sig, found := mod.ExportFunc(name)
	if !found {
		err = fmt.Errorf("export function %q not found", name)
		return
	}

	switch sig.Result {
	case wa.Void, wa.I32:
		// ok
		return

	default:
		err = fmt.Errorf("export function %q has wrong result type %s", name, sig.Result)
		return
	}
}
