// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package binding

import (
	"gate.computer/wag/compile"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/wa"
)

// EntryFunc looks up an export function which is suitable as an entry point.
// Its result type must be void or i32, and it must not take any parameters.
func EntryFunc(mod compile.Module, name string) (funcIndex uint32, err error) {
	funcIndex, sig, found := mod.ExportFunc(name)
	if !found {
		err = module.Errorf("entry function %q not found", name)
		return
	}

	if !IsEntryFuncType(sig) {
		err = module.Errorf("entry function %s%s has incompatible signature", name, sig)
		return
	}

	return
}

// IsEntryFuncType checks if the signature is suitable for an entry function.
func IsEntryFuncType(sig wa.FuncType) bool {
	if len(sig.Params) == 0 {
		if len(sig.Results) == 0 {
			return true
		}
		if len(sig.Results) == 1 && sig.Results[0] == wa.I32 {
			return true
		}
	}
	return false
}

// IsStartFuncType checks if the signature is suitable for a start function.
func IsStartFuncType(sig wa.FuncType) bool {
	return sig.Equal(wa.FuncType{})
}
