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
	var e werrors.PublicError
	if !errors.As(err, &e) {
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
	var e werrors.ModuleError
	if !errors.As(err, &e) {
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
	var e werrors.ResourceLimit
	if !errors.As(err, &e) {
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

type publicError struct {
	s       string
	public  string
	wrapped error
}

var _ werrors.PublicError = (*publicError)(nil)

func (e *publicError) Error() string       { return e.s }
func (e *publicError) PublicError() string { return e.public }
func (e *publicError) Unwrap() error       { return e.wrapped }

func newPublicError(s string, x *Public) error {
	return &publicError{
		s:      s,
		public: x.Error,
	}
}

type moduleError struct {
	publicError
}

func (*moduleError) ModuleError() {}

var _ werrors.ModuleError = (*moduleError)(nil)

func newModuleError(s string, x *Public) error {
	e := &moduleError{publicError{
		s:      s,
		public: x.Error,
	}}
	if x.Module.UnexpectedEOF {
		e.wrapped = io.ErrUnexpectedEOF
	}
	return e
}

type resourceLimit struct {
	publicError
}

func (*resourceLimit) ResourceLimit() {}

var _ werrors.ResourceLimit = (*resourceLimit)(nil)

func newResourceLimit(s string, x *Public) error {
	e := &resourceLimit{publicError{
		s:      s,
		public: x.Error,
	}}
	if x.ResourceLimit.BufferSizeExceeded {
		e.wrapped = buffer.ErrSizeLimit
	}
	return e
}
