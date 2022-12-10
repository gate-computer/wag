// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package operand

import (
	"fmt"

	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/gen/debug"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/wa"
)

const (
	payloadDebug = uint64(0x0c7a0c707e7a7e55) // "octa octo teta tess"
)

type O struct {
	Storage             storage.Storage
	Type                wa.Type
	UnreachableFallback bool

	payload uint64
}

func Placeholder(t wa.Type) (o O) {
	o.Storage = storage.Imm // Least dangerous
	o.Type = t
	if debug.Enabled {
		o.payload = payloadDebug
	}
	return
}

func Imm(t wa.Type, value uint64) O {
	return O{
		Storage: storage.Imm,
		Type:    t,
		payload: value,
	}
}

func Reg(t wa.Type, r reg.R) O {
	return O{
		Storage: storage.Reg,
		Type:    t,
		payload: uint64(byte(r)),
	}
}

func Flags(cond condition.C) O {
	return O{
		Storage: storage.Flags,
		Type:    wa.I32,
		payload: uint64(cond),
	}
}

func UnreachableSentinel() O {
	return O{
		Storage: storage.Unreachable,
	}
}

func UnreachableFallback(t wa.Type) O {
	return O{
		Storage:             storage.Imm,
		Type:                t,
		UnreachableFallback: true,
	}
}

func (o O) Size() wa.Size {
	return o.Type.Size()
}

func (o *O) SetPlaceholder() {
	o.Storage = storage.Imm // Least dangerous
	if debug.Enabled {
		o.payload = payloadDebug
	}
}

func (o *O) SetReg(r reg.R) {
	o.Storage = storage.Reg
	o.payload = uint64(r)
}

func (o *O) SetStack() {
	o.Storage = storage.Stack
}

func (o O) ImmValue() int64 {
	if o.Size() == wa.Size32 {
		return int64(int32(uint32(o.payload)))
	} else {
		return int64(o.payload)
	}
}

func (o O) ImmValue8() int8        { return int8(uint8(o.payload)) }
func (o O) Reg() reg.R             { return reg.R(byte(o.payload)) }
func (o O) FlagsCond() condition.C { return condition.C(int(o.payload)) }

func (o O) String() string {
	if o.UnreachableFallback {
		return fmt.Sprintf("unreachable fallback %s", o.Type)
	}

	if debug.Enabled && o.payload == payloadDebug {
		if o.Storage == storage.Imm {
			return fmt.Sprintf("%s placeholder", o.Type)
		} else {
			return fmt.Sprintf("magic %s value 0x%08x surprisingly in %s storage", o.Type, o.payload, o.Storage)
		}
	}

	switch o.Storage {
	case storage.Imm:
		if o.Type.Category() == wa.Int {
			return fmt.Sprintf("constant %s 0x%x", o.Type, o.payload)
		} else {
			return fmt.Sprintf("constant %s bits 0x%x", o.Type, o.payload)
		}

	case storage.Stack:
		return fmt.Sprintf("saved %s in stack", o.Type)

	case storage.Reg:
		if o.Reg() == reg.Result {
			return fmt.Sprintf("volatile %s in result register", o.Type)
		} else {
			return fmt.Sprintf("allocated %s in %s", o.Type, o.Reg())
		}

	case storage.Flags:
		return fmt.Sprintf("volatile %s comparison result", o.FlagsCond())

	case storage.Unreachable:
		return "unreachable sentinel"

	default:
		return "<invalid operand>"
	}
}
