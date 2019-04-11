// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package module

import (
	"fmt"
	"io"
)

type moduleError string

func Error(text string) error {
	return moduleError(text)
}

func Errorf(format string, args ...interface{}) error {
	return moduleError(fmt.Sprintf(format, args...))
}

func (s moduleError) Error() string       { return string(s) }
func (s moduleError) ModuleError() string { return string(s) }

type wrappedError struct {
	text  string
	cause error
}

func WrapError(cause error, text string) error {
	return &wrappedError{text, cause}
}

func (e *wrappedError) Error() string       { return e.text }
func (e *wrappedError) ModuleError() string { return e.text }
func (e *wrappedError) Unwrap() error       { return e.cause }

var ErrUnexpectedEOF unexpectedEOF

type unexpectedEOF struct{}

func (unexpectedEOF) Error() string       { return io.ErrUnexpectedEOF.Error() }
func (unexpectedEOF) ModuleError() string { return io.ErrUnexpectedEOF.Error() }
func (unexpectedEOF) Unwrap() error       { return io.ErrUnexpectedEOF }
