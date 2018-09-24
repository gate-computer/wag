// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build aix android dragonfly freebsd linux netbsd openbsd solaris

package file

import (
	"github.com/tsavola/wag/object/file/elf"
)

type File = elf.File
