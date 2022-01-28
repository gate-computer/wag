// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package errors exports common error types without unnecessary dependencies.
package errors

import (
	"errors"
)

// PublicError provides a message which can be used in communications.  The
// Error() method returns a message suitable for internal logging etc.
//
// If the PublicError methods an empty string, the error is effectively not
// public.
type PublicError interface {
	error
	PublicError() string
}

// AsPublicError returns the error if it is public (PublicError method returns
// non-empty string).
func AsPublicError(err error) PublicError {
	var e PublicError
	if errors.As(err, &e) && e.PublicError() != "" {
		return e
	}
	return nil
}

// ModuleError indicates that the error is caused by unsupported or malformed
// WebAssembly module.
type ModuleError interface {
	PublicError
	ModuleError() bool
}

// AsModuleError returns the error if it is a module error (ModuleError method
// returns true).
func AsModuleError(err error) ModuleError {
	var e ModuleError
	if errors.As(err, &e) && e.ModuleError() {
		return e
	}
	return nil
}

// ResourceLimit was reached.
type ResourceLimit interface {
	PublicError
	ResourceLimit() bool
}

// AsResourceLimit returns the error if it is a resource limit error
// (ResourceLimit method returns true).
func AsResourceLimit(err error) ResourceLimit {
	var e ResourceLimit
	if errors.As(err, &e) && e.ResourceLimit() {
		return e
	}
	return nil
}
