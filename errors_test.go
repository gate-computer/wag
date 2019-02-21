// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"testing"

	"github.com/tsavola/wag/buffer"
	"github.com/tsavola/wag/internal/module"
)

func TestErrorTypes(*testing.T) {
	type moduleError interface {
		error
		ModuleError() string
	}

	type bufferSizeError interface {
		moduleError
		BufferSizeLimit() string
	}

	var _ = module.Error("").(moduleError)
	var _ bufferSizeError = buffer.ErrSizeLimit
	var _ bufferSizeError = buffer.ErrStaticSize
}
