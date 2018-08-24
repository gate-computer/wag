// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import (
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/trap"
)

type Prog struct {
	FuncLinks []link.FuncL
	TrapLinks [trap.NumTraps]link.L
}
