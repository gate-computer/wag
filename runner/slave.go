package runner

import (
	"encoding/binary"
	"io"
	"os"

	"github.com/tsavola/wag/internal/types"
)

func (e *Executor) slave(fd int, sigs map[int64]types.Function, printer io.Writer, cont <-chan struct{}) {
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

		default:
			panic(command)
		}
	}
}
