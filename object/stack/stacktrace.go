// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/tsavola/wag/wa"
)

type TextMap interface {
	FindAddr(retAddr uint32) (init bool, funcIndex, callIndex int, stackOffset int32, retInsnPos uint32)
}

type Frame struct {
	FuncIndex  int
	RetInsnPos int      // Zero if information is not available.
	Locals     []uint64 // If function signatures are available.
}

func Trace(stack []byte, textAddr uint64, textMap TextMap, funcSigs []wa.FuncType) (stacktrace []Frame, err error) {
	if n := len(stack); n == 0 || n&7 != 0 {
		err = fmt.Errorf("invalid stack size %d", n)
		return
	}

	for len(stack) > 0 {
		absRetAddr := binary.LittleEndian.Uint64(stack[:8])

		retAddr := absRetAddr - textAddr
		if retAddr > math.MaxUint32 {
			err = fmt.Errorf("return address 0x%x is not in text section", absRetAddr)
			return
		}

		init, funcIndex, callIndex, stackOffset, retInsnPos := textMap.FindAddr(uint32(retAddr))
		if init {
			if callIndex < 0 {
				err = fmt.Errorf("unknown initial call return address 0x%x", retAddr)
			} else if stackOffset != 8 {
				err = fmt.Errorf("initial function call site 0x%x has inconsistent stack offset %d", retAddr, stackOffset)
			}
			return
		}

		if stackOffset < 0 {
			err = fmt.Errorf("unknown return address 0x%x", retAddr)
			return
		}
		if funcIndex < 0 {
			err = fmt.Errorf("function not found for return address 0x%x", retAddr)
			return
		}
		if stackOffset == 0 || stackOffset&7 != 0 {
			err = fmt.Errorf("invalid stack offset %d", stackOffset)
			return
		}

		var locals []uint64

		if funcSigs != nil {
			numParams := len(funcSigs[funcIndex].Params)
			numOthers := int(stackOffset/8) - 1
			numLocals := numParams + numOthers
			locals = make([]uint64, numLocals)

			for i := 0; i < numParams; i++ {
				locals[i] = binary.LittleEndian.Uint64(stack[(numLocals-i+1)*8:])
			}

			for i := 0; i < numOthers; i++ {
				locals[numParams+i] = binary.LittleEndian.Uint64(stack[(numOthers-i)*8:])
			}
		}

		stacktrace = append(stacktrace, Frame{
			FuncIndex:  funcIndex,
			RetInsnPos: int(retInsnPos),
			Locals:     locals,
		})

		stack = stack[stackOffset:]
	}

	err = errors.New("ran out of stack before initial call")
	return
}
