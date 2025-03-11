// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buffer implements compile.CodeBuffer and compile.DataBuffer.
package buffer

// ErrSizeLimit (or its wrapper) is propagated by buffer methods by panicking,
// or returned by compiler functions when used with panicking buffer
// implementations.
var ErrSizeLimit error = err{}

type err struct{}

func (err) Error() string       { return "buffer size limit exceeded" }
func (err) PublicError() string { return "buffer size limit exceeded" }
func (err) ResourceLimit() bool { return true }
