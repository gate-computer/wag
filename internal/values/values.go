package values

import (
	"strconv"
)

func I32(x interface{}) uint32 {
	s := x.(string)

	signed64, err := strconv.ParseInt(s, 0, 32)
	if err == nil {
		return uint32(signed64)
	}

	unsigned64, err := strconv.ParseUint(s, 0, 32)
	if err == nil {
		return uint32(unsigned64)
	}

	panic(err)
}

func I64(x interface{}) uint64 {
	s := x.(string)

	signed64, err := strconv.ParseInt(s, 0, 64)
	if err == nil {
		return uint64(signed64)
	}

	unsigned64, err := strconv.ParseUint(s, 0, 64)
	if err == nil {
		return unsigned64
	}

	panic(err)
}
