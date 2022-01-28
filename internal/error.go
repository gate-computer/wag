// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"io"

	"import.name/pan"
)

func Error(x interface{}) error {
	err := pan.Error(x)
	if err == nil {
		return nil
	}

	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return unexpectedEOF{}
	}

	return err
}

type unexpectedEOF struct{}

func (unexpectedEOF) Error() string       { return "unexpected EOF" }
func (unexpectedEOF) PublicError() string { return "unexpected EOF" }
func (unexpectedEOF) ModuleError() bool   { return true }
func (unexpectedEOF) Unwrap() error       { return io.ErrUnexpectedEOF }
