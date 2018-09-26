// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"encoding/binary"
	"io"

	"github.com/tsavola/wag/internal/errorpanic"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/reader"
	"github.com/tsavola/wag/internal/section"
)

// CopyKnownSection with the given type if one is found.  The returned length
// includes the copied section's header and payload (everything that was
// written).  Unknown sections preceding the known section are processed by
// unknownLoader (or discarded if it's nil) - they are not included in the
// returned length.  If another known section type is found, it is left
// untouched (the reader will be backed up before the section id) and zero
// length is returned.  If no known section is encountered, zero length and
// io.EOF are returned.  io.EOF is returned only when it occurs between
// sections.
func CopyKnownSection(w io.Writer, r reader.R, id Id, unknownLoader func(r Reader, payloadLen uint32) error) (length int64, err error) {
	defer func() {
		if x := recover(); x != nil {
			err = errorpanic.Handle(x)
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
		}
	}()

	load := loader.L{R: r}

	switch section.Find(id, load, unknownLoader) {
	case id:
		length, err = copySection(w, id, load)

	case 0:
		err = io.EOF
	}
	return
}

func copySection(w io.Writer, id Id, load loader.L) (length int64, err error) {
	payloadLen := load.Varuint32()

	head := make([]byte, 1+binary.MaxVarintLen32)
	head[0] = byte(id)
	n := binary.PutUvarint(head[1:], uint64(payloadLen))

	n, err = w.Write(head[:1+n])
	length += int64(n)
	if err != nil {
		return
	}

	m, err := io.CopyN(w, load.R, int64(payloadLen))
	length += m
	return
}
