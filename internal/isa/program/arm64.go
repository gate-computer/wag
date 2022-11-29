// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64

package program

const (
	NumTrapLinkRewindSuspended = 1
	NumTrapLinkTruncOverflow   = 0
)
