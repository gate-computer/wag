// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type TextMap interface {
	FindAddr(retAddr int32) (funcIndex, retInsnIndex, stackOffset int32, initialCall, ok bool)
}

type Frame struct {
	FuncIndex    int
	RetInsnIndex int // Zero if information is not available.
}

func Trace(stack []byte, textAddr uint64, textMap TextMap) (stacktrace []Frame, err error) {
	if n := len(stack); n == 0 || n&7 != 0 {
		err = fmt.Errorf("invalid stack size %d", n)
		return
	}

	for len(stack) > 0 {
		absRetAddr := binary.LittleEndian.Uint64(stack[:8])

		retAddr := absRetAddr - textAddr
		if retAddr > 0x7ffffffe {
			err = fmt.Errorf("return address 0x%x is not in text section", absRetAddr)
			return
		}

		funcIndex, retInsnIndex, stackOffset, initial, ok := textMap.FindAddr(int32(retAddr))
		if !ok {
			err = fmt.Errorf("call instruction not found for return address 0x%x", retAddr)
			return
		}

		if initial {
			if stackOffset != 8 {
				err = fmt.Errorf("initial function call site 0x%x has inconsistent stack offset %d", retAddr, stackOffset)
			}
			return
		}

		if stackOffset == 0 || stackOffset&7 != 0 {
			err = fmt.Errorf("invalid stack offset %d", stackOffset)
			return
		}

		stacktrace = append(stacktrace, Frame{
			FuncIndex:    int(funcIndex),
			RetInsnIndex: int(retInsnIndex),
		})

		stack = stack[stackOffset:]
	}

	err = errors.New("ran out of stack before initial call")
	return
}
