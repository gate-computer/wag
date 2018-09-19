// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wa

type FuncType struct {
	Params []Type
	Result Type
}

func (f1 FuncType) Equal(f2 FuncType) bool {
	if f1.Result != f2.Result {
		return false
	}

	if len(f1.Params) != len(f2.Params) {
		return false
	}

	for i := range f1.Params {
		if f1.Params[i] != f2.Params[i] {
			return false
		}
	}

	return true
}

func (f FuncType) String() (s string) {
	s = "("
	for i, t := range f.Params {
		if i > 0 {
			s += ", "
		}
		s += t.String()
	}
	s += ")"
	if f.Result != Void {
		s += " " + f.Result.String()
	}
	return
}
