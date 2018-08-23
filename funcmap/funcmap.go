// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package funcmap

import (
	"github.com/tsavola/wag/meta"
)

// Map implements Mapper.  It stores all function addresses, but no instruction
// information.
type Map struct {
	FuncAddrs []meta.TextAddr
}

func (m *Map) InitModule(numImportFuncs, numOtherFuncs int) {
	m.FuncAddrs = make([]meta.TextAddr, 0, numImportFuncs+numOtherFuncs)
}

func (m *Map) PutImportFunc(addr meta.TextAddr) {
	m.PutFunc(addr)
}

func (m *Map) PutFunc(addr meta.TextAddr) {
	m.FuncAddrs = append(m.FuncAddrs, addr)
}

func (*Map) PutCall(meta.TextAddr, int32) {}
func (*Map) PutInsn(meta.TextAddr)        {}
