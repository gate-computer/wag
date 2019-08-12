// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

DATA state+0(SB)/8, $0   // arg
DATA state+8(SB)/4, $-1  // slave_fd
DATA state+12(SB)/4, $-1 // result_fd
GLOBL state(SB), NOPTR, $16
