// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buffer implements compile.CodeBuffer and compile.DataBuffer.
package buffer

var ErrSizeLimit error = &SizeError{"buffer size limit exceeded"}

type SizeError struct {
	s string
}

func (e *SizeError) Error() string       { return e.s }
func (e *SizeError) ModuleError() string { return e.s }
