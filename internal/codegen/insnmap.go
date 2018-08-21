// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

type InsnMap interface {
	Init(numFuncs int)
	PutFunc(pos int32)
	PutInsn(pos int32)
}
