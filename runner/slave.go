package runner

import (
	"encoding/binary"
	"io"
	"os"

	"github.com/tsavola/wag/internal/types"
)

func (r *Runner) slave(fd int, sigs map[int64]types.Function, printer io.Writer) {
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
			r.snapshot(f, printer)

		default:
			panic(command)
		}
	}
}
