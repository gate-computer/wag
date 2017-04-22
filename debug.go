package wag

import (
	"fmt"
)

const (
	debug = false
)

var (
	debugDepth int
)

func debugf(format string, args ...interface{}) {
	if debugDepth < 0 {
		panic("negative debugDepth")
	}

	if debug {
		for i := 0; i < debugDepth; i++ {
			fmt.Print("  ")
		}

		fmt.Printf(format+"\n", args...)
	}
}
