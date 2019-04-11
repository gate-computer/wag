// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package errorpanic

import (
	"io"
	"runtime"

	internal "github.com/tsavola/wag/internal/errors"
	"golang.org/x/xerrors"
)

var errUnexpectedEOF = internal.WrapError(io.ErrUnexpectedEOF, io.ErrUnexpectedEOF.Error())

func Handle(x interface{}) (err error) {
	if x != nil {
		err, _ = x.(error)
		if err == nil {
			panic(x)
		}

		if _, ok := err.(runtime.Error); ok {
			panic(x)
		}

		switch {
		case xerrors.Is(err, io.EOF):
			err = errUnexpectedEOF
		}
	}

	return
}
