// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Errors
//
// Some errors returned by wag implement the following interface:
//
//     interface {
//         ModuleError() string
//     }
//
// Presence of the ModuleError method indicates that the error is caused by
// unsupported or malformed WebAssembly module.  Other errors returned by
// compilation functions are either read errors or internal compiler errors.
// Unexpected EOF is a ModuleError which wraps io.ErrUnexpectedEOF.
//
// Default buffer implementations use the buffer.ErrSizeLimit error to
// indicates that generated code or data doesn't fit in a target buffer.  It is
// also a ModuleError (the module didn't conform to size constraints).
//
package wag
