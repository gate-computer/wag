package ins

import (
	"fmt"
)

func ImmI32(x interface{}) uint32 {
	switch v := x.(type) {
	case int64:
		return uint32(v)

	case uint64:
		return uint32(v)

	default:
		panic(fmt.Errorf("bad immediate operand for i32: %t", x))
	}
}

func ImmI64(x interface{}) uint64 {
	switch v := x.(type) {
	case int64:
		return uint64(v)

	case uint64:
		return v

	default:
		panic(fmt.Errorf("bad immediate operand for i64: %t", x))
	}
}
