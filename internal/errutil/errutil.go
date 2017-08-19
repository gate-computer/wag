// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package errutil

import (
	"runtime"
)

func ErrorOrPanic(x interface{}) (err error) {
	if x != nil {
		err, _ = x.(error)
		if err == nil {
			panic(x)
		}

		if _, ok := err.(runtime.Error); ok {
			panic(x)
		}
	}

	return
}
