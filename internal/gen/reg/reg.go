// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reg

import (
	"fmt"
)

type R byte

func (r R) String() string {
	return fmt.Sprintf("r%d", r)
}

const (
	Result     = R(0)
	ScratchISA = R(1) // for internal ISA implementation use
)
