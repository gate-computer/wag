package wag

import (
	"fmt"
	"io"
	"io/ioutil"
)

// CopyCodeSection if there is one.  Unknown sections preceding the code
// section are silently discarded.  If another known section type is found, it
// is left untouched (the reader will be backed up before the section id).
func CopyCodeSection(w io.Writer, r Reader) (ok bool, err error) {
	defer func() {
		if x := recover(); x != nil {
			if err, _ = x.(error); err == nil {
				panic(x)
			}
		}
	}()

	ok = copyCodeSection(w, r)
	return
}

func copyCodeSection(W io.Writer, R Reader) (ok bool) {
	w := writer{W}
	r := reader{R}

loop:
	for {
		id := r.readByte()

		switch {
		case id == sectionCode:
			w.writeByte(id)
			break loop

		case id == sectionUnknown:
			payloadLen := r.readVaruint32()
			if _, err := io.CopyN(ioutil.Discard, r, int64(payloadLen)); err != nil {
				panic(err)
			}

		case int(id) < numSections:
			r.UnreadByte()
			return

		default:
			panic(fmt.Errorf("unknown section id: %d", id))
		}
	}

	payloadLen := r.readVaruint32()
	w.writeVaruint32(payloadLen)

	if _, err := io.CopyN(w, r, int64(payloadLen)); err != nil {
		panic(err)
	}

	ok = true
	return
}
