// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package imports

import (
	"fmt"

	"github.com/tsavola/wag/abi"
)

type Function struct {
	abi.FunctionType
	Variadic bool
	AbsAddr  uint64
}

func (impl Function) Implements(signature abi.FunctionType) bool {
	if impl.Variadic {
		return equalTypesVariadic(impl.FunctionType, signature)
	} else {
		return equalTypes(impl.FunctionType, signature)
	}
}

func (f Function) String() (s string) {
	s = fmt.Sprintf("0x%x (", f.AbsAddr)
	for i, t := range f.Args {
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

func compareTypes(sig1, sig2 abi.FunctionType) int {
	len1 := len(sig1.Args)
	len2 := len(sig2.Args)

	if len1 < len2 {
		return -1
	}
	if len1 > len2 {
		return 1
	}

	return compareTypePrefixes(sig1, sig2, len1)
}

func equalTypes(sig1, sig2 abi.FunctionType) bool {
	return compareTypes(sig1, sig2) == 0
}

func equalTypesVariadic(partial, complete abi.FunctionType) bool {
	minLen := len(partial.Args)

	if len(complete.Args) < minLen {
		return false
	}

	return compareTypePrefixes(partial, complete, minLen) == 0
}

func compareTypePrefixes(sig1, sig2 abi.FunctionType, numArgs int) int {
	for i := 0; i < numArgs; i++ {
		arg1 := sig1.Args[i]
		arg2 := sig2.Args[i]

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
