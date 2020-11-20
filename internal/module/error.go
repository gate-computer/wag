// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package module

import (
	internal "gate.computer/wag/internal/errors"
)

func Error(text string) error {
	return internal.ModuleError(text)
}

func Errorf(format string, args ...interface{}) error {
	return internal.ModuleErrorf(format, args...)
}

func WrapError(cause error, text string) error {
	return internal.WrapModuleError(cause, text)
}
