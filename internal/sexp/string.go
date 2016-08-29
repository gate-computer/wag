package sexp

import (
	"fmt"
)

func Stringify(x interface{}) string {
	return stringify(x, "")
}

func stringify(x interface{}, indent string) (s string) {
	indent += "  "

	switch x := x.(type) {
	case []interface{}:
		s += "("

		wrap := false

		for i, item := range x {
			if _, ok := item.([]interface{}); ok {
				wrap = true
			}

			if wrap {
				s += "\n" + indent
			} else if i > 0 {
				s += " "
			}

			s += stringify(item, indent)
		}

		s += ")"

	default:
		s += fmt.Sprint(x)
	}

	return
}
