package runner

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/tsavola/wag/types"
)

func (e *Executor) slave(fd int, sigs []types.Function, printer io.Writer, cont <-chan struct{}) {
	f := os.NewFile(uintptr(fd), "socket")
	defer f.Close()

	for {
		var command int64

		if err := binary.Read(f, byteOrder, &command); err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		switch {
		case command >= 0:
			spectestPrint(f, sigs, command, printer)

		case command == -1:
			e.runner.snapshot(f, printer)

		case command == -2:
			<-cont
			if _, err := f.Write([]byte{0}); err != nil {
				panic(err)
			}

		case command == -3:
			putns(f, printer)

		default:
			panic(command)
		}
	}
}

func putns(f io.Reader, printer io.Writer) {
	var count uint32

	if err := binary.Read(f, byteOrder, &count); err != nil {
		panic(err)
	}

	buf := make([]byte, count)

	if _, err := f.Read(buf); err != nil {
		panic(err)
	}

	if _, err := fmt.Fprintf(printer, "putns: %#v\n", string(buf)); err != nil {
		panic(err)
	}
}
