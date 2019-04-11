// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package errors

import (
	"fmt"
)

type ModuleError struct {
	text  string
	cause error
}

func Error(text string) error {
	return &ModuleError{text, nil}
}

func Errorf(format string, args ...interface{}) error {
	return &ModuleError{fmt.Sprintf(format, args...), nil}
}

func WrapError(cause error, text string) error {
	return &ModuleError{text, cause}
}

func (e *ModuleError) Error() string       { return e.text }
func (e *ModuleError) ModuleError() string { return e.text }
func (e *ModuleError) Unwrap() error       { return e.cause }
