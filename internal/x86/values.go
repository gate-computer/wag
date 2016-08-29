package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/values"
)

var byteOrder = binary.LittleEndian

func encodeUint32(x uint32) (b []byte) {
	b = make([]byte, 4)
	byteOrder.PutUint32(b, x)
	return
}

func encodeUint64(x uint64) (b []byte) {
	b = make([]byte, 8)
	byteOrder.PutUint64(b, x)
	return
}

func encodeI32(x interface{}) []byte {
	return encodeUint32(values.I32(x))
}

func encodeI64(x interface{}) []byte {
	return encodeUint64(values.I64(x))
}
