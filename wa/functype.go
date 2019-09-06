// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wa

type FuncType struct {
	Params []Type
	Result Type
}

func (f FuncType) Equal(other FuncType) bool {
	if f.Result != other.Result {
		return false
	}

	if len(f.Params) != len(other.Params) {
		return false
	}

	for i := range f.Params {
		if f.Params[i] != other.Params[i] {
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
