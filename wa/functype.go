// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wa

type FuncType struct {
	Params  []Type
	Results []Type
}

func (f FuncType) Equal(other FuncType) bool {
	if len(f.Params) != len(other.Params) {
		return false
	}
	if len(f.Results) != len(other.Results) {
		return false
	}

	for i := range f.Params {
		if f.Params[i] != other.Params[i] {
			return false
		}
	}

	for i := range f.Results {
		if f.Results[i] != other.Results[i] {
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

	switch len(f.Results) {
	case 0:
	case 1:
		s += " " + f.Results[0].String()
	default:
		s += " ("
		for i, t := range f.Results {
			if i > 0 {
				s += ", "
			}
			s += t.String()
		}
		s += ")"
	}

	return
}
