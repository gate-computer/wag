// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wag provides a high-level WebAssembly compiler API.
//
// See the Compile function's source code for an example of how to use the
// low-level compiler APIs (implemented in subpackages).
//
// Errors
//
// ModuleError type is accessible via errors subpackage.  Such errors may be
// returned by compilation and other parsing functions.  Other types of errors
// indicate either a read error or an internal compiler error.  Unexpected EOF
// is a ModuleError which wraps io.ErrUnexpectedEOF.
//
// Default buffer implementations use the buffer.ErrSizeLimit error to indicate
// that generated code or data doesn't fit in a target buffer.  It is a
// ModuleError (the module didn't conform to size constraints).
//
package wag
