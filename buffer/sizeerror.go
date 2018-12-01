// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buffer implements compile.CodeBuffer and compile.DataBuffer.
package buffer

type sizeError string

func (s sizeError) Error() string           { return string(s) }
func (s sizeError) ModuleError() string     { return string(s) }
func (s sizeError) BufferSizeLimit() string { return string(s) }

// Errors implementing interface{ BufferSizeLimit() string }.
var (
	ErrSizeLimit  = sizeError("buffer size limit exceeded")
	ErrStaticSize = sizeError("static buffer capacity exceeded")
)
