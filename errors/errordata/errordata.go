// Copyright (c) 2022 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package errordata helps with error serialization.
package errordata

import (
	"errors"
	"io"

	"gate.computer/wag/buffer"
	werrors "gate.computer/wag/errors"
)

// Internal details of an error.
type Internal struct {
	Error  string  `json:"error,omitempty"` // Omitted if same as public error.
	Public *Public `json:"public,omitempty"`
}

// Deconstruct an error on best-effort basis.
func Deconstruct(err error) *Internal {
	if pub := deconstructModule(err); pub != nil {
		return newInternalWithPublic(err, pub)
	}
	if pub := deconstructResourceLimit(err); pub != nil {
		return newInternalWithPublic(err, pub)
	}
	if pub := deconstructPublic(err); pub != nil { // Must be last.
		return newInternalWithPublic(err, pub)
	}

	return &Internal{
		Error: err.Error(),
	}
}

func newInternalWithPublic(err error, pub *Public) *Internal {
	x := &Internal{
		Public: pub,
	}
	if s := err.Error(); s != pub.Error {
		x.Error = s
	}
	return x
}

// GetPublic representation which is well-formed even if there are no public
// details.
func (x *Internal) GetPublic() *Public {
	if x.Public != nil {
		return x.Public
	}

	return &Public{
		Error: "internal error",
	}
}

// Reconstruct an error.
func (x *Internal) Reconstruct() error {
	if x.Public == nil {
		return errors.New(x.Error)
	}

	s := x.Public.Error
	if x.Error != "" {
		s = x.Error
	}
	return reconstructError(s, x.Public)
}

// Public details of an error.
type Public struct {
	Error         string         `json:"error"`
	Module        *Module        `json:"module,omitempty"`
	ResourceLimit *ResourceLimit `json:"resource_limit,omitempty"`
}

func deconstructPublic(err error) *Public {
	e := werrors.AsPublicError(err)
	if e == nil {
		return nil
	}

	return &Public{
		Error: e.PublicError(),
	}
}

// Reconstruct an error without internal details.
func (x *Public) Reconstruct() error {
	return reconstructError(x.Error, x)
}

// Module error details.
type Module struct {
	UnexpectedEOF bool `json:"unexpected_eof,omitempty"`
}

func deconstructModule(err error) *Public {
	e := werrors.AsModuleError(err)
	if e == nil {
		return nil
	}

	return &Public{
		Error: e.PublicError(),
		Module: &Module{
			UnexpectedEOF: errors.Is(err, io.ErrUnexpectedEOF),
		},
	}
}

// ResourceLimit error details.
type ResourceLimit struct {
	BufferSizeExceeded bool `json:"buffer_size_exceeded,omitempty"`
}

func deconstructResourceLimit(err error) *Public {
	e := werrors.AsResourceLimit(err)
	if e == nil {
		return nil
	}

	return &Public{
		Error: e.PublicError(),
		ResourceLimit: &ResourceLimit{
			BufferSizeExceeded: errors.Is(err, buffer.ErrSizeLimit),
		},
	}
}

func reconstructError(s string, x *Public) error {
	if x.Module != nil {
		return newModuleError(s, x)
	}
	if x.ResourceLimit != nil {
		return newResourceLimit(s, x)
	}
	return newPublicError(s, x)
}

type dataError struct {
	s      string
	public string
	module bool
	rlimit bool
	inner  error
}

var _ werrors.PublicError = (*dataError)(nil)
var _ werrors.ModuleError = (*dataError)(nil)
var _ werrors.ResourceLimit = (*dataError)(nil)

func (e *dataError) Error() string       { return e.s }
func (e *dataError) PublicError() string { return e.public }
func (e *dataError) ModuleError() bool   { return e.module }
func (e *dataError) ResourceLimit() bool { return e.rlimit }
func (e *dataError) Unwrap() error       { return e.inner }

func newPublicError(s string, x *Public) error {
	return &dataError{
		s:      s,
		public: x.Error,
	}
}

func newModuleError(s string, x *Public) error {
	e := &dataError{
		s:      s,
		public: x.Error,
		module: true,
	}
	if x.Module.UnexpectedEOF {
		e.inner = io.ErrUnexpectedEOF
	}
	return e
}

func newResourceLimit(s string, x *Public) error {
	e := &dataError{
		s:      s,
		public: x.Error,
		rlimit: true,
	}
	if x.ResourceLimit.BufferSizeExceeded {
		e.inner = buffer.ErrSizeLimit
	}
	return e
}
