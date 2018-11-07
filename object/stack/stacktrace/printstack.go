// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stacktrace

import (
	"fmt"
	"io"

	"github.com/tsavola/wag/object/stack"
	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/wa"
)

func Fprint(w io.Writer, stacktrace []stack.Frame, funcTypes []wa.FuncType, names *section.NameSection) (err error) {
	for depth, frame := range stacktrace {
		var name string

		if names != nil && int(frame.FuncIndex) < len(names.FuncNames) {
			name = names.FuncNames[frame.FuncIndex].FuncName
		} else {
			name = fmt.Sprintf("func.%d", frame.FuncIndex)
		}

		var suffix string

		if frame.RetInsnIndex != 0 {
			callInsnIndex := frame.RetInsnIndex - 1
			suffix = fmt.Sprintf(" +%d", callInsnIndex)
		}

		_, err = fmt.Fprintf(w, "#%-2d %s%s\n", depth, name, suffix)
		if err != nil {
			return
		}
	}

	return
}
