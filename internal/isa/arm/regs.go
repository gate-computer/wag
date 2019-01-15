// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"fmt"
	"runtime"

	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/isa/arm/in"
)

const (
	RegResult         = reg.Result
	RegScratch        = reg.ScratchISA
	RegImportVariadic = reg.R(2)  // <- AllocIntFirst
	_                 = reg.R(25) // <- AllocIntLast
	RegMemoryBase     = reg.R(26)
	RegTextBase       = reg.R(27)
	RegStackLimit4    = reg.R(28)
	RegSuspendBit     = reg.R(28) // 0 = suspend
	RegFakeSP         = in.RegFakeSP
	RegLink           = reg.R(30)
	RegRealSP         = reg.R(31)
	RegZero           = reg.R(31)
	RegDiscard        = reg.R(31)
)

//go:noinline
func TODO(args ...interface{}) interface{} {
	msg := "TODO"
	if len(args) > 0 {
		msg = "TODO: " + fmt.Sprint(args...)
	}
	if _, file, line, ok := runtime.Caller(1); ok {
		panic(fmt.Errorf("%s:%d: %s", file, line, msg))
	} else {
		panic(msg)
	}
}
