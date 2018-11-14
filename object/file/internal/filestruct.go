// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

// File represents a standalone executable program.
type File struct {
	Runtime       []byte
	RuntimeAddr   uint64
	EntryAddr     uint32
	EntryArgs     []uint64
	Text          []byte
	GlobalsMemory []byte
	MemoryOffset  int
}
