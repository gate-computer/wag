// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"github.com/tsavola/wag/internal/codegen"
)

type InsnMap = codegen.InsnMap

type dummyInsnMap struct{}

func (dummyInsnMap) Init(numFuncs int) {}
func (dummyInsnMap) PutFunc(pos int32) {}
func (dummyInsnMap) PutInsn(pos int32) {}
