// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !cgo

package dump

import (
	"errors"
	"io"

	"github.com/tsavola/wag/section"
)

func Text(w io.Writer, text []byte, textAddr uintptr, funcAddrs []uint32, ns *section.NameSection) error {
	return errors.New("object/debug/dump.Text requires cgo")
}
