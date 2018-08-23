// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package abi

type FunctionType struct {
	Args   []Type
	Result Type
}

func (f1 FunctionType) Equal(f2 FunctionType) bool {
	if f1.Result != f2.Result {
		return false
	}

	if len(f1.Args) != len(f2.Args) {
		return false
	}

	for i := range f1.Args {
		if f1.Args[i] != f2.Args[i] {
			return false
		}
	}

	return true
}

func (f FunctionType) String() (s string) {
	s = "("
	for i, t := range f.Args {
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
