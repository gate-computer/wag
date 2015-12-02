package wag

import (
	"fmt"
)

func asError(x interface{}) error {
	switch y := x.(type) {
	case error:
		return y

	default:
		return fmt.Errorf("%v", x)
	}
}
