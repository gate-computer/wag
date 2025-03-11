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
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/pan"
)

func TestPublicError(t *testing.T) {
	if err := error(publicError{}); werrors.AsPublicError(err) == nil {
		t.Error(err)
	}

	if err := error(nonpublicError{}); werrors.AsPublicError(err) != nil {
		t.Error(err)
	}
}

func TestModuleError(t *testing.T) {
	_ = module.Error("").(werrors.ModuleError)
	_ = module.Errorf("").(werrors.ModuleError)
	_ = module.WrapError(errors.New(""), "").(werrors.ModuleError)

	err := errors.New("")
	if unwrapped := errors.Unwrap(module.WrapError(err, "")); unwrapped != err {
		t.Error(unwrapped)
	}
}

func TestInternalErrorEOF(t *testing.T) {
	err := pan.Error(pan.Wrap(io.EOF))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error(err)
	}

	if werrors.AsModuleError(err) == nil {
		t.Error(err)
	}
}

func TestBufferSizeLimit(t *testing.T) {
	_ = buffer.ErrSizeLimit.(werrors.ResourceLimit)

	wrapped := fmt.Errorf("wrapped: %w", buffer.ErrSizeLimit)
	if !errors.Is(wrapped, buffer.ErrSizeLimit) {
		t.Error(wrapped)
	}

	if e := werrors.AsResourceLimit(wrapped); e != nil {
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
	if werrors.AsPublicError(err) != nil {
		t.Error(err)
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
	if e := werrors.AsPublicError(err); e != nil {
		if e.PublicError() != "public message" {
			t.Error(err)
		}
	} else {
		t.Error(err)
	}
	if errors.Unwrap(err) != nil {
		t.Error(err)
	}

	err = errordata.Deconstruct(publicError{}).Public.Reconstruct()
	if err.Error() != "public message" {
		t.Error(err)
	}
	if e := werrors.AsPublicError(err); e != nil {
		if e.PublicError() != "public message" {
			t.Error(err)
		}
	} else {
		t.Error(err)
	}
}

func TestModuleErrorData(t *testing.T) {
	err := errordata.Deconstruct(module.Error("foo")).Reconstruct()
	if err.Error() != "foo" {
		t.Error(err)
	}
	if e := werrors.AsModuleError(err); e != nil {
		if e.PublicError() != "foo" {
			t.Error(err)
		}
	} else {
		t.Error(err)
	}
	if errors.Unwrap(err) != nil {
		t.Error(err)
	}

	err = errordata.Deconstruct(pan.Error(pan.Wrap(io.EOF))).Reconstruct()
	if werrors.AsModuleError(err) == nil {
		t.Error(err)
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
	if e := werrors.AsResourceLimit(err); e != nil {
		if e.PublicError() != buffer.ErrSizeLimit.Error() {
			t.Error(err)
		}
	} else {
		t.Error(err)
	}
	if !errors.Is(err, buffer.ErrSizeLimit) {
		t.Error(err)
	}

	err = errordata.Deconstruct(fmt.Errorf("wrapped: %w", buffer.ErrSizeLimit)).Reconstruct()
	if werrors.AsResourceLimit(err) == nil {
		t.Error(err)
	}
	if !errors.Is(err, buffer.ErrSizeLimit) {
		t.Error(err)
	}
}

type publicError struct{}

func (publicError) Error() string       { return "internal message" }
func (publicError) PublicError() string { return "public message" }

type nonpublicError struct{}

func (nonpublicError) Error() string       { return "message" }
func (nonpublicError) PublicError() string { return "" }
