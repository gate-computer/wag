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
// Read errors (such as EOF) are passed though as is.
//
// Errors implementing the following interface indicate that generated code or
// data doesn't fit in a target buffer:
//
//     interface {
//         BufferSizeLimit() string
//     }
//
// (Buffer size limit errors implement also the ModuleError method.)
//
package wag
