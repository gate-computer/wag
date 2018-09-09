// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/bnagy/gapstone"
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/static"
)

type rmRegReg interface {
	RegReg(text *code.Buf, t abi.Type, r, r2 reg.R)
}

type rmRegMemDisp interface {
	RegMemDisp(text *code.Buf, t abi.Type, r reg.R, base BaseReg, disp int32)
}
type rmRegMemIndexDisp interface {
	RegMemIndexDisp(text *code.Buf, t abi.Type, r reg.R, base BaseReg, index reg.R, s Scale, disp int32)
}

type rmRegStack interface {
	RegStack(text *code.Buf, t abi.Type, r reg.R)
}
type rmRegStackDisp interface {
	RegStackDisp(text *code.Buf, t abi.Type, r reg.R, disp int32)
}
type rmRegStackDisp8 interface {
	RegStackDisp8(text *code.Buf, t abi.Type, r reg.R, disp int8)
}
type rmRegStackStub32 interface {
	RegStackStub32(text *code.Buf, t abi.Type, r reg.R)
}

func init() {
	var (
		_ rmRegReg          = RM(0)
		_ rmRegMemDisp      = RM(0)
		_ rmRegMemIndexDisp = RM(0)
		_ rmRegStackDisp    = RM(0)
		_ rmRegStackDisp8   = RM(0)
		_ rmRegStackStub32  = RM(0)
	)
	var (
		_ rmRegReg       = RM2(0)
		_ rmRegMemDisp   = RM2(0)
		_ rmRegStack     = RM2(0)
		_ rmRegStackDisp = RM2(0)
	)
	var (
		_ rmRegReg       = RMprefix(0)
		_ rmRegMemDisp   = RMprefix(0)
		_ rmRegStack     = RMprefix(0)
		_ rmRegStackDisp = RMprefix(0)
	)
}

var (
	testEngine gapstone.Engine
)

func init() {
	engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
	if err != nil {
		panic(err)
	}

	err = engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)
	if err != nil {
		panic(err)
	}

	testEngine = engine
}

func testEncode(t *testing.T, expectMnemonic, expectOpStr string, encodeInsn func(*code.Buf)) {
	t.Helper()

	testEncodeImm(t, expectMnemonic, expectOpStr, nil, encodeInsn)
}

func testEncodeImm(t *testing.T, expectMnemonic, expectOpStr string, expectImm interface{}, encodeInsn func(*code.Buf)) {
	t.Helper()

	text := code.Buf{
		Buffer: static.Buf(make([]byte, 16)),
	}

	encodeInsn(&text)

	insns, err := testEngine.Disasm(text.Bytes(), 0, 0)
	if err != nil {
		t.Errorf("expect %s %s: %v", expectMnemonic, expectOpStr, err)
		return
	}

	insn := insns[0]

	if insn.Mnemonic == expectMnemonic {
		if expectImm == nil {
			if insn.OpStr == expectOpStr {
				return
			}
		} else {
			i := strings.Index(expectOpStr, "IMM")
			if insn.OpStr[:i] != expectOpStr[:i] {
				goto fail
			}
			expectTail := expectOpStr[i+3:]
			if insn.OpStr[len(insn.OpStr)-len(expectTail):] != expectTail {
				goto fail
			}
			valStr := insn.OpStr[i : len(insn.OpStr)-len(expectTail)]

			var (
				valU   uint64
				valS   int64
				signed bool
			)

			valU, err = strconv.ParseUint(valStr, 0, 64)
			if err != nil {
				valS, err = strconv.ParseInt(valStr, 0, 64)
				if err != nil {
					goto fail
				}
				signed = true
			}

			switch expectVal := expectImm.(type) {
			case int8:
				if signed {
					if int8(valS) == expectVal {
						return
					}
				} else {
					if int8(uint8(valU)) == expectVal {
						return
					}
				}

			case int16:
				if signed {
					if int16(valS) == expectVal {
						return
					}
				} else {
					if int16(uint16(valU)) == expectVal {
						return
					}
				}

			case int32:
				if signed {
					if int32(valS) == expectVal {
						return
					}
				} else {
					if int32(uint32(valU)) == expectVal {
						return
					}
				}

			case int64:
				if signed {
					if valS == expectVal {
						return
					}
				} else {
					if int64(valU) == expectVal {
						return
					}
				}

			default:
				panic(expectVal)
			}
		}
	}

fail:
	if expectImm != nil {
		expectOpStr = strings.Replace(expectOpStr, "IMM", fmt.Sprintf("%#x", expectImm), 1)
	}

	t.Errorf("%s %s <> %s %s", expectMnemonic, expectOpStr, insn.Mnemonic, insn.OpStr)
}

func opStr(xs ...interface{}) (s string) {
	for i, x := range xs {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprint(x)
	}
	return
}

func opStrSwapIf(mr bool, xs ...interface{}) (s string) {
	if !mr {
		return opStr(xs...)
	}

	for i := len(xs) - 1; i >= 0; i-- {
		if i < len(xs)-1 {
			s += ", "
		}
		s += fmt.Sprint(xs[i])
	}
	return
}

func optimalImm(val int32) interface{} {
	if val >= -128 && val < 128 {
		return int8(val)
	} else {
		return val
	}
}
