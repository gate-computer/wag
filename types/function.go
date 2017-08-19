// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

type Function struct {
	Args   []T
	Result T
}

func (f1 Function) Compare(f2 Function) int {
	len1 := len(f1.Args)
	len2 := len(f2.Args)

	if len1 < len2 {
		return -1
	}
	if len1 > len2 {
		return 1
	}

	return f1.comparePrefix(f2, len1)
}

func (f1 Function) Equal(f2 Function) bool {
	return f1.Compare(f2) == 0
}

func (partial Function) EqualVariadic(complete Function) bool {
	minLen := len(partial.Args)

	if len(complete.Args) < minLen {
		return false
	}

	return partial.comparePrefix(complete, minLen) == 0
}

func (f1 Function) comparePrefix(f2 Function, numArgs int) int {
	for i := 0; i < numArgs; i++ {
		arg1 := f1.Args[i]
		arg2 := f2.Args[i]

		if arg1 < arg2 {
			return -1
		}
		if arg1 > arg2 {
			return 1
		}
	}

	res1 := f1.Result
	res2 := f2.Result

	if res1 < res2 {
		return -1
	}
	if res1 > res2 {
		return 1
	}

	return 0
}

func (f Function) String() string {
	return f.StringWithNames(nil)
}

func (f Function) StringWithNames(localNames []string) (s string) {
	s = "("
	for i, t := range f.Args {
		if i > 0 {
			s += ", "
		}
		if i < len(localNames) {
			s += localNames[i] + " "
		}
		s += t.String()
	}
	s += ")"
	if f.Result != Void {
		s += " " + f.Result.String()
	}
	return
}
