// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buffer implements compile.CodeBuffer and compile.DataBuffer.
package buffer

import (
	module "github.com/tsavola/wag/internal/errors"
)

var ErrSizeLimit = module.Error("buffer size limit exceeded")
