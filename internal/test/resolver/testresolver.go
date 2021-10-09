// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"fmt"
	"math"
	"strings"

	"gate.computer/gate/runtime/abi/rt"
	"gate.computer/wag/compile"
	"gate.computer/wag/wa"
)

type L struct{}

func (L) ResolveFunc(module, field string, sig wa.FuncType) (int, error) {
	m, found := rt.ImportFuncs()[module]
	if !found {
		panic(module)
	}

	index, found := m[field]
	if !found {
		panic(field)
	}

	return index, nil
}

type M struct {
	L compile.Library
}

func (reso M) ResolveFunc(module, field string, expectSig wa.FuncType) (uint32, error) {
	symbol := module + "_" + strings.Replace(strings.Replace(field, "->", "_to_", -1), "-", "_", -1)

	index, actualSig, found := reso.L.ExportFunc(symbol)
	if !found {
		return 0, fmt.Errorf("unknown function imported: %q.%q", module, field)
	}

	if !expectSig.Equal(actualSig) {
		return 0, fmt.Errorf("function %s.%s%s imported with wrong type: %s", module, field, actualSig, expectSig)
	}

	return index, nil
}

func (reso M) ResolveGlobal(module, field string, t wa.Type) (uint64, error) {
	switch module {
	case "spectest":
		switch field {
		case "global_i32":
			if t == wa.I32 {
				return 666, nil
			}

		case "global_i64":
			if t == wa.I64 {
				return 666, nil
			}

		case "global_f32":
			if t == wa.F32 {
				return uint64(math.Float32bits(666)), nil
			}

		case "global_f64":
			if t == wa.F64 {
				return math.Float64bits(666), nil
			}

		default:
			return 0, fmt.Errorf("unknown global imported: %q.%q", module, field)
		}

	case "test":
		switch field {
		case "global-i32":
			if t == wa.I32 {
				return 0, nil
			}

		case "global-f32":
			if t == wa.F32 {
				return 0, nil
			}

		default:
			return 0, fmt.Errorf("unknown global imported: %q.%q", module, field)
		}

	default:
		return 0, fmt.Errorf("unknown global imported: %q.%q", module, field)
	}

	return 0, fmt.Errorf("global %s.%s imported with wrong type: %s", module, field, t)
}
