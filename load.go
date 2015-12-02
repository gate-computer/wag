package wag

import (
	"encoding/binary"
	"io"
)

type loader struct {
	buf []byte
}

func (l *loader) data(size int) (data []byte) {
	if len(l.buf) < size {
		panic(io.EOF)
	}
	data = l.buf[:size]
	l.buf = l.buf[size:]
	return
}

func (l *loader) int8() (value int8) {
	if len(l.buf) < 1 {
		panic(io.EOF)
	}
	value = int8(l.buf[0])
	l.buf = l.buf[1:]
	return
}

func (l *loader) uint8() (value uint8) {
	if len(l.buf) < 1 {
		panic(io.EOF)
	}
	value = l.buf[0]
	l.buf = l.buf[1:]
	return
}

func (l *loader) uint16() (value uint16) {
	if len(l.buf) < 2 {
		panic(io.EOF)
	}
	value = binary.LittleEndian.Uint16(l.buf[:2])
	l.buf = l.buf[2:]
	return
}

func (l *loader) uint32() (value uint32) {
	if len(l.buf) < 4 {
		panic(io.EOF)
	}
	value = binary.LittleEndian.Uint32(l.buf[:4])
	l.buf = l.buf[4:]
	return
}

func (l *loader) uint8log2int() int {
	return 1 << l.uint8()
}

func (l *loader) leb128() (c uint32, bits uint) {
	for i := 0; i < len(l.buf); i++ {
		byte := l.buf[i]
		c |= uint32(byte&0x7f) << bits
		bits += 7
		if byte&0x80 == 0 {
			l.buf = l.buf[i+1:]
			return c, bits
		}
		if i == 4 {
			panic("encoded integer is too long")
		}
	}
	panic(io.EOF)
}

func (l *loader) leb128uint32() (value uint32) {
	value, _ = l.leb128()
	return
}

func (l *loader) leb128int32() (value int32) {
	x, bits := l.leb128()
	value = int32(x)
	if value&(1<<(bits-1)) != 0 {
		value |= -1 << bits
	}
	return
}

func (l *loader) leb128size() (value int) {
	x, _ := l.leb128()
	value = int(x)
	if value < 0 {
		panic("unsigned integer value is too large for the implementation")
	}
	return
}
