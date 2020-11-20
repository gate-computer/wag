// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"gate.computer/wag/wa"
)

func spectestPrint(f io.Reader, sigs []wa.FuncType, sigIndex int64, printer io.Writer) {
	if sigIndex >= int64(len(sigs)) {
		panic(fmt.Sprintf("0x%x", sigIndex))
	}
	sig := sigs[sigIndex]

	args := make([]uint64, len(sig.Params))

	if err := binary.Read(f, byteOrder, args); err != nil {
		panic(err)
	}

	for i, t := range sig.Params {
		if i > 0 {
			if _, err := fmt.Fprint(printer, " "); err != nil {
				panic(err)
			}
		}

		x := args[len(args)-1-i] // arguments are laid out in reverse

		var err error

		switch t {
		case wa.I32:
			_, err = fmt.Fprintf(printer, "%d", int32(x))

		case wa.I64:
			_, err = fmt.Fprintf(printer, "%d", int64(x))

		case wa.F32:
			_, err = fmt.Fprintf(printer, "%f", math.Float32frombits(uint32(x)))

		case wa.F64:
			_, err = fmt.Fprintf(printer, "%f", math.Float64frombits(x))

		default:
			panic(t)
		}

		if err != nil {
			panic(err)
		}
	}

	if _, err := fmt.Fprintln(printer); err != nil {
		panic(err)
	}
}
