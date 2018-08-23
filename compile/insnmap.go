// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"github.com/tsavola/wag/meta"
)

type dummyInsnMap struct{}

func (dummyInsnMap) Init(numFuncs int)     {}
func (dummyInsnMap) PutFunc(meta.TextAddr) {}
func (dummyInsnMap) PutInsn(meta.TextAddr) {}
