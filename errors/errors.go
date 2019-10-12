// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package errors exports common error types without unnecessary dependencies.
package errors

// PublicError provides a message which can be used in communications.  The
// Error() method returns a message suitable for internal logging etc.
type PublicError interface {
	error
	PublicError() string
}

// ModuleError indicates that the error is caused by unsupported or malformed
// WebAssembly module.
type ModuleError interface {
	PublicError
	ModuleError()
}

// ResourceLimit was reached.
type ResourceLimit interface {
	PublicError
	ResourceLimit()
}
