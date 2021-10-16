// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64
// +build amd64 wagamd64
// +build !wagarm64

package program

const (
	NumTrapLinkRewindSuspended = 2
	NumTrapLinkTruncOverflow   = 4
)
