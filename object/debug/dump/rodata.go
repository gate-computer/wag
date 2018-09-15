// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dump

import (
	"encoding/binary"
	"fmt"
	"io"
)

func ROData(w io.Writer, roData []byte, roDataAddr uintptr) (err error) {
	fmt.Fprintf(w, "rodata:\n")

	for addr := roDataAddr; len(roData) > 0; {
		if roDataAddr == 0 { // relative
			fmt.Fprintf(w, "%8x", addr)
		} else {
			fmt.Fprintf(w, "%08x", addr)
		}

		for i := 0; i < 4 && len(roData) > 0; i++ {
			if len(roData) >= 8 {
				fmt.Fprintf(w, " %016x", binary.LittleEndian.Uint64(roData))
				roData = roData[8:]
				addr += 8
			} else {
				fmt.Fprintf(w, " ........%08x", binary.LittleEndian.Uint32(roData))
				roData = roData[4:]
				addr += 4
			}
		}

		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
	return
}
