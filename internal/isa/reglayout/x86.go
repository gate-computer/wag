// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build wagamd64 amd64,!wagarm64

package reglayout

const (
	AllocIntFirst = 5  // rbp
	AllocIntLast  = 13 // r13

	AllocFloatFirst = 2  // xmm2
	AllocFloatLast  = 15 // xmm15

	Radix = 16
)
