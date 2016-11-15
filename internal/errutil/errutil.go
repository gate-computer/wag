package errutil

import (
	"runtime"
)

func ErrorOrPanic(x interface{}) (err error) {
	if x != nil {
		err, _ = x.(error)
		if err == nil {
			panic(x)
		}

		if _, ok := err.(runtime.Error); ok {
			panic(x)
		}
	}

	return
}
