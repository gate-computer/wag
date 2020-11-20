// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"errors"
	"io"
	"testing"

	"gate.computer/wag/buffer"
	werrors "gate.computer/wag/errors"
	"gate.computer/wag/internal/errorpanic"
	"gate.computer/wag/internal/module"
	"golang.org/x/xerrors"
)

func TestModuleError(t *testing.T) {
	var _ = module.Error("").(werrors.ModuleError)
	var _ = module.Errorf("").(werrors.ModuleError)
	var _ = module.WrapError(errors.New(""), "").(werrors.ModuleError)

	err := errors.New("")
	if unwrapped := xerrors.Unwrap(module.WrapError(err, "")); unwrapped != err {
		t.Error(unwrapped)
	}
}

func TestErrorPanicEOF(t *testing.T) {
	err := errorpanic.Handle(io.EOF)
	if !xerrors.Is(err, io.ErrUnexpectedEOF) {
		t.Error(err)
	}

	var moduleError werrors.ModuleError
	if !xerrors.As(err, &moduleError) {
		t.Error(err)
	}
}

func TestBufferSizeLimit(t *testing.T) {
	var _ = buffer.ErrSizeLimit.(werrors.ResourceLimit)

	wrapped := xerrors.Errorf("wrapped: %w", buffer.ErrSizeLimit)
	if !xerrors.Is(wrapped, buffer.ErrSizeLimit) {
		t.Error(wrapped)
	}

	var moduleError werrors.ResourceLimit
	if xerrors.As(wrapped, &moduleError) {
		if moduleError != buffer.ErrSizeLimit {
			t.Error(moduleError)
		}
	} else {
		t.Error(wrapped)
	}
}
