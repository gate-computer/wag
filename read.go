package wag

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader interface {
	io.Reader
	io.ByteScanner
}

// reader provides panicking alternatives for Reader methods, and then some.
type reader struct {
	Reader
}

func (r reader) read(buf []byte) {
	if _, err := r.Read(buf); err != nil {
		panic(err)
	}
	debugReadf("read %d bytes: 0x%x", len(buf), buf)
	return
}

func (r reader) readN(n uint32) (data []byte) {
	data = make([]byte, n)
	r.read(data)
	return
}

func (r reader) readByte() byte {
	x, err := r.ReadByte()
	if err != nil {
		panic(err)
	}
	debugReadf("read byte: 0x%x", x)
	return x
}

func (r reader) readOpcode() opcode {
	return opcode(r.readByte())
}

func (r reader) readUint32() (x uint32) {
	if err := binary.Read(r, binary.LittleEndian, &x); err != nil {
		panic(err)
	}
	debugReadf("read uint32: 0x%x", x)
	return
}

func (r reader) readUint64() (x uint64) {
	if err := binary.Read(r, binary.LittleEndian, &x); err != nil {
		panic(err)
	}
	debugReadf("read uint64: 0x%x", x)
	return
}

func (r reader) readVarint32() int32 {
	return int32(r.readVarint64())
}

func (r reader) readVarint64() (x int64) {
	var shift uint
	for {
		b := r.readByte()
		x |= (int64(b) & 0x7f) << shift
		shift += 7
		if (b & 0x80) == 0 {
			if shift < 64 && (b&0x40) != 0 {
				x |= -1 << shift
			}
			return
		}
	}
}

func (r reader) readVaruint1() bool {
	x, err := r.ReadByte()
	if err != nil {
		panic(err)
	}
	if x > 1 {
		panic(fmt.Errorf("varuint1 is too large: 0x%x", x))
	}
	debugReadf("read varuint1: 0x%x", x)
	return x == 1
}

func (r reader) readVaruint7() (x uint8) {
	x, err := r.ReadByte()
	if err != nil {
		panic(err)
	}
	if x > math.MaxInt8 {
		panic(fmt.Errorf("varuint7 is too large: 0x%x", x))
	}
	debugReadf("read varuint7: 0x%x", x)
	return
}

func (r reader) readVaruint32() uint32 {
	x, err := binary.ReadUvarint(r)
	if err != nil {
		panic(err)
	}
	if x > math.MaxUint32 {
		panic(fmt.Errorf("varuint32 is too large: 0x%x", x))
	}
	debugReadf("read varuint32: 0x%x", x)
	return uint32(x)
}

func (r reader) readVaruint64() (x uint64) {
	x, err := binary.ReadUvarint(r)
	if err != nil {
		panic(err)
	}
	debugReadf("read varuint64: 0x%x", x)
	return
}

// readCount reads a varuint32 for iteration.
func (r reader) readCount() []struct{} {
	count := r.readVaruint32()
	if count > math.MaxInt32 {
		panic(fmt.Errorf("count is too large: 0x%x", count))
	}
	return make([]struct{}, int(count))
}
