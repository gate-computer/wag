// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"github.com/tsavola/wag/internal/mod"
	"github.com/tsavola/wag/object"
)

type ObjectMap = mod.ObjectMap

type dummyMap struct{}

func (dummyMap) InitObjectMap(int, int)             {}
func (dummyMap) PutImportFuncAddr(object.TextAddr)  {}
func (dummyMap) PutFuncAddr(object.TextAddr)        {}
func (dummyMap) PutCallSite(object.TextAddr, int32) {}
func (dummyMap) PutInsnAddr(object.TextAddr)        {}
