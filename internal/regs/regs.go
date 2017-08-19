// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regs

import (
	"fmt"
)

type R byte

func (reg R) String() string {
	return fmt.Sprintf("r%d", reg)
}
