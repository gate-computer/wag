// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package section

import (
	"encoding/binary"
	"io"

	"gate.computer/wag/internal/errorpanic"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/section"
)

// CopyStandardSection with the given type if one is found.  The returned
// length includes the copied section's header and payload (everything that was
// written).  Custom sections preceding the standard section are processed by
// customLoader (or discarded if it's nil) - they are not included in the
// returned length.  If another standard section type is found, it is left
// untouched (the reader will be backed up before the section id) and zero
// length is returned.  If no standard section is encountered, zero length and
// io.EOF are returned.  io.EOF is returned only when it occurs between
// sections.
func CopyStandardSection(w io.Writer, r Reader, id ID, customLoader func(r Reader, payloadLen uint32) error) (length int64, err error) {
	defer func() {
		if x := recover(); x != nil {
			err = errorpanic.Handle(x)
		}
	}()

	load := loader.L{R: r}

	switch section.Find(id, load, nil, customLoader) {
	case id:
		length, err = copySection(w, id, load)

	case 0:
		err = io.EOF
	}
	return
}

// SkipCustomSections until the next standard section.  The skipped sections
// are processed by customLoader (or discarded if it's nil).  If no standard
// section is encountered, io.EOF is returned.  io.EOF is returned only when it
// occurs between sections.
func SkipCustomSections(r Reader, customLoader func(Reader, uint32) error) (err error) {
	defer func() {
		if x := recover(); x != nil {
			err = errorpanic.Handle(x)
		}
	}()

	load := loader.L{R: r}

	if section.Find(0, load, nil, customLoader) == 0 {
		err = io.EOF
	}
	return
}

func copySection(w io.Writer, id ID, load loader.L) (length int64, err error) {
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
