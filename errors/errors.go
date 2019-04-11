// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package errors exports common error types without unnecessary dependencies.
package errors

import (
	internal "github.com/tsavola/wag/internal/errors"
)

// ModuleError indicates that the error is caused by unsupported or malformed
// WebAssembly module.  It may wrap an underlying error.
type ModuleError = internal.ModuleError
