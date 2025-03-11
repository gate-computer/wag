// Copyright (c) 2025 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pan

import (
	"io"

	"import.name/pan"
)

type unexpectedEOF struct{}

func (unexpectedEOF) Error() string       { return "unexpected EOF" }
func (unexpectedEOF) PublicError() string { return "unexpected EOF" }
func (unexpectedEOF) ModuleError() bool   { return true }
func (unexpectedEOF) Unwrap() error       { return io.ErrUnexpectedEOF }

var z = new(pan.Zone)

var Check = z.Check
var Panic = z.Panic
var Wrap = z.Wrap

func Error(x any) error {
	err := z.Error(x)
	if err == nil {
		return nil
	}

	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return unexpectedEOF{}
	}

	return err
}

func Must[T any](x T, err error) T {
	Check(err)
	return x
}
