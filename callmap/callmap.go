// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package callmap

import (
	"github.com/tsavola/wag/funcmap"
	"github.com/tsavola/wag/meta"
)

// Map implements Mapper.  It stores all function addresses and call sites, but
// no instruction information.
type Map struct {
	funcmap.Map
	CallSites []meta.CallSite
}

func (m *Map) InitModule(numImportFuncs, numOtherFuncs int) {
	m.Map.InitModule(numImportFuncs, numOtherFuncs)
	m.CallSites = make([]meta.CallSite, 0, numImportFuncs+numOtherFuncs) // conservative guess
}

func (m *Map) PutCallSite(retAddr meta.TextAddr, stackOffset int32) {
	m.CallSites = append(m.CallSites, meta.CallSite{
		ReturnAddr:  meta.TextAddr(retAddr),
		StackOffset: stackOffset,
	})
}
