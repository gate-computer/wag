// +build !amd64

package x86

import (
	"encoding/binary"
)

const Native = false

func (X86) PutUint32(b []byte, val uint32) {
	binary.LittleEndian.PutUint32(b, val)
}
