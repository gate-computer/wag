// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package module

import (
	"fmt"
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
