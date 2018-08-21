// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package function

import (
	"github.com/tsavola/wag/wasm"
)

type Type struct {
	Args   []wasm.Type
	Result wasm.Type
}

func (f Type) String() (s string) {
	s = "("
	for i, t := range f.Args {
		if i > 0 {
			s += ", "
		}
		s += t.String()
	}
	s += ")"
	if f.Result != wasm.Void {
		s += " " + f.Result.String()
	}
	return
}
