// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buffer implements compile.CodeBuffer and compile.DataBuffer.
package buffer

type sizeError string

func (sizeError) OutputSizeLimit() bool { return true }
func (s sizeError) Error() string       { return string(s) }
func (s sizeError) String() string      { return string(s) }

// These errors implement interface{ OutputSizeLimit() bool }.
var (
	ErrSizeLimit  = sizeError("buffer size limit exceeded")
	ErrStaticSize = sizeError("static buffer capacity exceeded")
)
