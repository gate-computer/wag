package reader

import (
	"io"
)

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader interface {
	io.Reader
	io.ByteScanner
}
