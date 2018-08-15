// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sexp

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func Stringify(x interface{}, multiline bool) string {
	return stringify(x, multiline, "")
}

func stringify(x interface{}, multiline bool, indent string) (s string) {
	indent += "  "

	switch x := x.(type) {
	case []interface{}:
		s += "("

		wrap := false

		for i, item := range x {
			if _, ok := item.([]interface{}); ok {
				wrap = true
			}

			if wrap && multiline {
				s += "\n" + indent
			} else if i > 0 {
				s += " "
			}

			s += stringify(item, multiline, indent)
		}

		s += ")"

	default:
		s += fmt.Sprint(x)
	}

	return
}

func Unparse(expr []interface{}) []byte {
	var buf bytes.Buffer
	unparse(expr, &buf)
	return buf.Bytes()
}

func unparse(expr interface{}, buf *bytes.Buffer) {
	switch x := expr.(type) {
	case string:
		if _, err := buf.Write([]byte(x)); err != nil {
			panic(err)
		}

	case Quoted:
		var data []byte
		var err error

		manual := false

		for _, b := range []byte(x.String()) {
			if b < 32 || b > 127 {
				manual = true
				break
			}
		}

		if manual {
			data = []byte{'"'}

			for _, b := range []byte(x.String()) {
				if b < 32 || b > 127 {
					data = append(data, fmt.Sprintf("\\%02x", b)...)
				} else {
					data = append(data, b)
				}
			}

			data = append(data, '"')
		} else {
			data, err = json.Marshal(x.String())
			if err != nil {
				panic(err)
			}
		}

		if _, err := buf.Write(data); err != nil {
			panic(err)
		}

	case []interface{}:
		if _, err := buf.Write([]byte("(")); err != nil {
			panic(err)
		}
		for i, child := range x {
			unparse(child, buf)
			if i < len(x)-1 {
				if _, err := buf.Write([]byte(" ")); err != nil {
					panic(err)
				}
			}
		}
		if _, err := buf.Write([]byte(") ")); err != nil {
			panic(err)
		}

	default:
		panic(expr)
	}
}
