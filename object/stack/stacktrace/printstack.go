// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stacktrace

import (
	"debug/dwarf"
	"fmt"
	"io"

	"github.com/tsavola/wag/object/stack"
	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/wa"
)

func Fprint(w io.Writer, stacktrace []stack.Frame, funcSigs []wa.FuncType, names *section.NameSection, debug *dwarf.Data) (err error) {
	var debugLines map[int]string

	if debug != nil {
		debugLines, err = parseDWARF(debug)
		if err != nil {
			return
		}
	}

	var (
		depthWidth  int
		offsetWidth int
	)

	for depth, frame := range stacktrace {
		if n := len(fmt.Sprintf("%d", depth)); n > depthWidth {
			depthWidth = n
		}
		if n := len(fmt.Sprintf("%x", frame.RetOffset)); n > offsetWidth {
			offsetWidth = n
		}
	}

	if depthWidth < 2 {
		depthWidth = 2
	}
	if offsetWidth&1 == 1 {
		offsetWidth++
	}

	var (
		lineFmt   = fmt.Sprintf("#%%-%dd %%s%%s%%s\n", depthWidth)
		prefixFmt = fmt.Sprintf("0x%%0%dx in ", offsetWidth)
	)

	for depth, frame := range stacktrace {
		var name string

		if names != nil && int(frame.FuncIndex) < len(names.FuncNames) {
			name = names.FuncNames[frame.FuncIndex].FuncName
		} else {
			name = fmt.Sprintf("function %d", frame.FuncIndex)
		}

		var (
			prefix string
			suffix string
		)

		if frame.RetOffset != 0 {
			callOffset := frame.RetOffset - 1
			prefix = fmt.Sprintf(prefixFmt, callOffset)

			if debugLines != nil {
				if s := getLine(debugLines, frame.RetOffset); s != "" {
					suffix = fmt.Sprintf(" at %s", s)
				}
			}
		}

		_, err = fmt.Fprintf(w, lineFmt, depth, prefix, name, suffix)
		if err != nil {
			return
		}

		if frame.Locals != nil {
			var values string

			delim := "       0  "

			for i, x := range frame.Locals {
				if i&3 == 3 {
					values += fmt.Sprintf("%s%016x", delim, x)
					delim = fmt.Sprintf("\n%8d  ", i+1)
				} else {
					values += fmt.Sprintf("%s%016x", delim, x)
					delim = " "
				}
			}

			if values != "" {
				_, err = fmt.Fprintln(w, values)
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func parseDWARF(data *dwarf.Data) (map[int]string, error) {
	lines := make(map[int]string)

	r := data.Reader()

	for {
		e, err := r.Next()
		if err != nil {
			return nil, err
		}
		if e == nil {
			break
		}

		if e.Tag == dwarf.TagCompileUnit {
			if e.Children {
				lr, err := data.LineReader(e)
				if err != nil {
					return nil, err
				}

				if lr != nil {
					var le dwarf.LineEntry

					for {
						if err := lr.Next(&le); err != nil {
							if err == io.EOF {
								break
							}
							return nil, err
						}

						lines[int(le.Address)] = fmt.Sprintf("%s:%d", le.File.Name, le.Line)
					}
				}
			}
		} else {
			if e.Children {
				r.SkipChildren()
			}
		}
	}

	return lines, nil
}

func getLine(lines map[int]string, offset int) string {
	for ; offset > 0; offset-- {
		s, found := lines[offset]
		if found {
			return s
		}
	}

	return ""
}
