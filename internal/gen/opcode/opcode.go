// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opcode

import (
	"fmt"
)

type Opcode byte

func (op Opcode) String() (s string) {
	s = Strings[op]
	if s == "" {
		s = fmt.Sprintf("0x%02x", byte(op))
	}
	return
}
