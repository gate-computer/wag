// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"gate.computer/wag/buffer"
	werrors "gate.computer/wag/errors"
	"gate.computer/wag/errors/errordata"
	"gate.computer/wag/internal"
	"gate.computer/wag/internal/module"
	"import.name/pan"
)

func TestModuleError(t *testing.T) {
	var _ = module.Error("").(werrors.ModuleError)
	var _ = module.Errorf("").(werrors.ModuleError)
	var _ = module.WrapError(errors.New(""), "").(werrors.ModuleError)

	err := errors.New("")
	if unwrapped := errors.Unwrap(module.WrapError(err, "")); unwrapped != err {
		t.Error(unwrapped)
	}
}

func TestInternalErrorEOF(t *testing.T) {
	err := internal.Error(pan.Wrap(io.EOF))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error(err)
	}

	var e werrors.ModuleError
	if !errors.As(err, &e) {
		t.Error(err)
	}
}

func TestBufferSizeLimit(t *testing.T) {
	var _ = buffer.ErrSizeLimit.(werrors.ResourceLimit)

	wrapped := fmt.Errorf("wrapped: %w", buffer.ErrSizeLimit)
	if !errors.Is(wrapped, buffer.ErrSizeLimit) {
		t.Error(wrapped)
	}

	var e werrors.ResourceLimit
	if errors.As(wrapped, &e) {
		if e != buffer.ErrSizeLimit {
			t.Error(e)
		}
	} else {
		t.Error(wrapped)
	}
}

func TestErrorData(t *testing.T) {
	err := errordata.Deconstruct(io.EOF).Reconstruct()
	if err.Error() != io.EOF.Error() {
		t.Error(err)
	}
	{
		var e werrors.PublicError
		if errors.As(err, &e) {
			t.Error(err)
		}
	}
	if errors.Unwrap(err) != nil {
		t.Error(err)
	}

	err = errordata.Deconstruct(io.EOF).GetPublic().Reconstruct()
	if err.Error() == io.EOF.Error() {
		t.Error(err)
	}
}

func TestPublicErrorData(t *testing.T) {
	err := errordata.Deconstruct(publicError{}).Reconstruct()
	if err.Error() != "internal message" {
		t.Error(err)
	}
	{
		var e werrors.PublicError
		if errors.As(err, &e) {
			if e.PublicError() != "public message" {
				t.Error(err)
			}
		} else {
			t.Error(err)
		}
	}
	if errors.Unwrap(err) != nil {
		t.Error(err)
	}

	err = errordata.Deconstruct(publicError{}).Public.Reconstruct()
	if err.Error() != "public message" {
		t.Error(err)
	}
	{
		var e werrors.PublicError
		if errors.As(err, &e) {
			if e.PublicError() != "public message" {
				t.Error(err)
			}
		} else {
			t.Error(err)
		}
	}
}

func TestModuleErrorData(t *testing.T) {
	err := errordata.Deconstruct(module.Error("foo")).Reconstruct()
	if err.Error() != "foo" {
		t.Error(err)
	}
	{
		var e werrors.ModuleError
		if errors.As(err, &e) {
			if e.PublicError() != "foo" {
				t.Error(err)
			}
		} else {
			t.Error(err)
		}
	}
	if errors.Unwrap(err) != nil {
		t.Error(err)
	}

	err = errordata.Deconstruct(internal.Error(pan.Wrap(io.EOF))).Reconstruct()
	{
		var e werrors.ModuleError
		if !errors.As(err, &e) {
			t.Error(err)
		}
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error(err)
	}
}

func TestResourceLimitData(t *testing.T) {
	err := errordata.Deconstruct(buffer.ErrSizeLimit).Reconstruct()
	if err.Error() != buffer.ErrSizeLimit.Error() {
		t.Error(err)
	}
	{
		var e werrors.ResourceLimit
		if errors.As(err, &e) {
			if e.PublicError() != buffer.ErrSizeLimit.Error() {
				t.Error(err)
			}
		} else {
			t.Error(err)
		}
	}
	if !errors.Is(err, buffer.ErrSizeLimit) {
		t.Error(err)
	}

	err = errordata.Deconstruct(fmt.Errorf("wrapped: %w", buffer.ErrSizeLimit)).Reconstruct()
	{
		var e werrors.ResourceLimit
		if !errors.As(err, &e) {
			t.Error(err)
		}
	}
	if !errors.Is(err, buffer.ErrSizeLimit) {
		t.Error(err)
	}
}

type publicError struct{}

func (publicError) Error() string       { return "internal message" }
func (publicError) PublicError() string { return "public message" }
