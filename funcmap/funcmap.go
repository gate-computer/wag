// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package funcmap

import (
	"github.com/tsavola/wag/meta"
)

// Map implements Mapper.  It stores all function addresses, but no call or
// instruction information.
type Map struct {
	FuncAddrs []meta.TextAddr
}

func (m *Map) InitModule(numImportFuncs, numOtherFuncs int) {
	m.FuncAddrs = make([]meta.TextAddr, 0, numImportFuncs+numOtherFuncs)
}

func (m *Map) PutImportFuncAddr(addr meta.TextAddr) {
	m.PutFuncAddr(addr)
}

func (m *Map) PutFuncAddr(addr meta.TextAddr) {
	m.FuncAddrs = append(m.FuncAddrs, addr)
}

func (*Map) PutCallAddr(meta.TextAddr, int32) {}
func (*Map) PutInsnAddr(meta.TextAddr)        {}
