// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"errors"
	"io"
	"testing"

	"github.com/tsavola/wag/buffer"
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
	var _ moduleError = module.ErrUnexpectedEOF

	if !xerrors.Is(module.ErrUnexpectedEOF, io.ErrUnexpectedEOF) {
		t.Error(module.ErrUnexpectedEOF)
	}
}

func TestErrorPanicEOF(t *testing.T) {
	if err := errorpanic.Handle(io.EOF); !xerrors.Is(err, module.ErrUnexpectedEOF) {
		t.Error(err)
	}
}

type bufferSizeError interface {
	moduleError
	BufferSizeLimit() string
}

func TestBufferSizeError(t *testing.T) {
	var _ = buffer.ErrSizeLimit.(moduleError)

	wrapped := xerrors.Errorf("wrapped: %w", buffer.ErrSizeLimit)
	if !xerrors.Is(wrapped, buffer.ErrSizeLimit) {
		t.Error(wrapped)
	}

	var sizeError *buffer.SizeError
	if xerrors.As(wrapped, &sizeError) {
		if sizeError != buffer.ErrSizeLimit {
			t.Error(sizeError)
		}
	} else {
		t.Error(wrapped)
	}
}
