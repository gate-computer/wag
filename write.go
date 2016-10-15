package wag

import (
	"encoding/binary"
	"io"
)

// writer provides a panicking alternative for the Write method, and then some.
type writer struct {
	io.Writer
}

func (w writer) write(data []byte) {
	if _, err := w.Write(data); err != nil {
		panic(err)
	}
	return
}

func (w writer) writeByte(b byte) {
	w.write([]byte{b})
}

func (w writer) writeVaruint32(x uint32) {
	buf := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(buf, uint64(x))
	w.write(buf[:n])
}
