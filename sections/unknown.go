package sections

import (
	"errors"
	"io"
	"io/ioutil"

	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/reader"
)

const (
	maxSectionNameLen = 255 // TODO
)

type UnknownLoader func(string, reader.Reader) error

type UnknownLoaders map[string]UnknownLoader

func (uls UnknownLoaders) Load(r reader.Reader, payloadLen uint32) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	load := loader.L{r}

	nameLen := load.Varuint32()
	if nameLen > maxSectionNameLen {
		panic(errors.New("unknown section name is too long"))
	}

	name := string(load.Bytes(nameLen))

	if f := uls[name]; f != nil {
		if err := f(name, load); err != nil {
			panic(err)
		}
	} else {
		if _, err := io.CopyN(ioutil.Discard, load, int64(payloadLen)); err != nil {
			panic(err)
		}
	}

	return
}
