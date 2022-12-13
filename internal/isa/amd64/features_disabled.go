// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wagamd64

package amd64

func haveLZCNT() bool  { return false }
func havePOPCNT() bool { return false }
func haveTZCNT() bool  { return false }
