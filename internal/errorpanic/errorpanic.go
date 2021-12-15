// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package errorpanic

import (
	"io"
	"runtime"
)

func Handle(x interface{}) (err error) {
	if x != nil {
		err, _ = x.(error)
		if err == nil {
			panic(x)
		}

		if _, ok := err.(runtime.Error); ok {
			panic(x)
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = unexpectedEOF{}
		}
	}

	return
}

type unexpectedEOF struct{}

func (unexpectedEOF) Error() string       { return "unexpected EOF" }
func (unexpectedEOF) PublicError() string { return "unexpected EOF" }
func (unexpectedEOF) ModuleError()        {}
func (unexpectedEOF) Unwrap() error       { return io.ErrUnexpectedEOF }
