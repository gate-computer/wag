// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package errors

import (
	"fmt"
)

type moduleError struct {
	text  string
	cause error
}

func ModuleError(text string) error {
	return &moduleError{text, nil}
}

func ModuleErrorf(format string, args ...interface{}) error {
	return &moduleError{fmt.Sprintf(format, args...), nil}
}

func WrapModuleError(cause error, text string) error {
	return &moduleError{text, cause}
}

func (e *moduleError) Error() string       { return e.text }
func (e *moduleError) PublicError() string { return e.text }
func (e *moduleError) ModuleError() bool   { return true }
func (e *moduleError) Unwrap() error       { return e.cause }
