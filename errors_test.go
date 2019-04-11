// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"errors"
	"io"
	"testing"

	"github.com/tsavola/wag/buffer"
	wagerrors "github.com/tsavola/wag/errors"
	"github.com/tsavola/wag/internal/errorpanic"
	"github.com/tsavola/wag/internal/module"
	"golang.org/x/xerrors"
)

type moduleError interface {
	error
	ModuleError() string
}

func TestModuleError(t *testing.T) {
	var _ = module.Error("").(moduleError)
	var _ = module.Errorf("").(moduleError)
	var _ = module.WrapError(errors.New(""), "").(moduleError)

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

	var moduleError *wagerrors.ModuleError
	if !xerrors.As(err, &moduleError) {
		t.Error(err)
	}
}

func TestBufferSizeLimit(t *testing.T) {
	var _ = buffer.ErrSizeLimit.(moduleError)

	wrapped := xerrors.Errorf("wrapped: %w", buffer.ErrSizeLimit)
	if !xerrors.Is(wrapped, buffer.ErrSizeLimit) {
		t.Error(wrapped)
	}

	var moduleError *wagerrors.ModuleError
	if xerrors.As(wrapped, &moduleError) {
		if moduleError != buffer.ErrSizeLimit {
			t.Error(moduleError)
		}
	} else {
		t.Error(wrapped)
	}
}
