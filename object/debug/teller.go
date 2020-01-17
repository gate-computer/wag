// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"github.com/tsavola/wag/internal/reader"
)

// Teller knows the position.
type Teller interface {
	Tell() int64
}

// ReadTeller is a reader which knows how many bytes have been read.
type ReadTeller interface {
	reader.R
	Teller
}

// NewReadTeller wraps a reader into one which tracks the read position.
func NewReadTeller(r reader.R) ReadTeller {
	return &reader.Counter{R: r}
}
