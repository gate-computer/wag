package sexp

import (
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
