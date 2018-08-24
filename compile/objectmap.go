// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"github.com/tsavola/wag/internal/obj"
)

type ObjectMap = obj.Map

type dummyMap struct{}

func (dummyMap) InitObjectMap(int, int)   {}
func (dummyMap) PutImportFuncAddr(int32)  {}
func (dummyMap) PutFuncAddr(int32)        {}
func (dummyMap) PutCallSite(int32, int32) {}
func (dummyMap) PutInsnAddr(int32)        {}
