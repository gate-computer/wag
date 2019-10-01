// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package imports

import (
	"fmt"

	"github.com/tsavola/wag/wa"
)

type Func struct {
	VecIndex  int
	Addr      uint64
	Suspender bool
	Variadic  bool
	wa.FuncType
}

func (impl Func) Implements(signature wa.FuncType) bool {
	if impl.Variadic {
		return equalTypesVariadic(impl.FuncType, signature)
	} else {
		return equalTypes(impl.FuncType, signature)
	}
}

func (f Func) String() (s string) {
	s = fmt.Sprintf("0x%x (", f.Addr)
	for i, t := range f.Params {
		if i > 0 {
			s += ", "
		}
		s += t.String()
	}
	if f.Variadic {
		s += "..."
	}
	s += ") " + f.Result.String()
	return
}

func compareTypes(sig1, sig2 wa.FuncType) int {
	len1 := len(sig1.Params)
	len2 := len(sig2.Params)

	if len1 < len2 {
		return -1
	}
	if len1 > len2 {
		return 1
	}

	return compareTypePrefixes(sig1, sig2, len1)
}

func equalTypes(sig1, sig2 wa.FuncType) bool {
	return compareTypes(sig1, sig2) == 0
}

func equalTypesVariadic(partial, complete wa.FuncType) bool {
	minLen := len(partial.Params)

	if len(complete.Params) < minLen {
		return false
	}

	return compareTypePrefixes(partial, complete, minLen) == 0
}

func compareTypePrefixes(sig1, sig2 wa.FuncType, numParams int) int {
	for i := 0; i < numParams; i++ {
		arg1 := sig1.Params[i]
		arg2 := sig2.Params[i]

		if arg1 < arg2 {
			return -1
		}
		if arg1 > arg2 {
			return 1
		}
	}

	res1 := sig1.Result
	res2 := sig2.Result

	if res1 < res2 {
		return -1
	}
	if res1 > res2 {
		return 1
	}

	return 0
}
