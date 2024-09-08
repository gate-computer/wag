// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

//go:generate go run gate.computer/cmd/gate-resource -d include include/rt.h
//go:generate go run gate.computer/cmd/gate-librarian library.wasm -- library/compile.sh -c -o /dev/stdout
