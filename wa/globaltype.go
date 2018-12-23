// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wa

type GlobalType byte

func MakeGlobalType(t Type, mutable bool) (g GlobalType) {
	g = GlobalType(t)
	if mutable {
		g |= 0x80
	}
	return
}

func (g GlobalType) Type() Type    { return Type(g & 0x7f) }
func (g GlobalType) Mutable() bool { return g&0x80 != 0 }

// Encode as WebAssembly.  Result is undefined if GlobalType representation is
// not valid.
func (g GlobalType) Encode() (buf [2]byte) {
	buf[0] = g.Type().Encode()
	if g.Mutable() {
		buf[1] = 1
	}
	return
}
