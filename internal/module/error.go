// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package module

import (
	internal "github.com/tsavola/wag/internal/errors"
)

func Error(text string) error {
	return internal.Error(text)
}

func Errorf(format string, args ...interface{}) error {
	return internal.Errorf(format, args...)
}

func WrapError(cause error, text string) error {
	return internal.WrapError(cause, text)
}
