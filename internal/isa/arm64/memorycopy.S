// Copyright (c) 2024 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

.globl _start

// Input:
//	[x29, #24]: target address within wasm memory (32-bit)
//	[x29, #16]: source address within wasm memory (32-bit)
//	[x29, #8]:  region length (32-bit)
//	x0:         wasm memory pages
//	x26:        wasm memory address
//
// Output:
//	w0: nonzero causes trap
//
// Must be preserved:
//	x26
//	x27
//	x28
//	x29

_start:
	// Arguments
	ldr	w2, [x29, #24]
	ldr	w3, [x29, #16]
	ldr	w4, [x29, #8]

	// Bounds checks
	add	x5, x2, x4
	cmp	x5, x0, lsl #16
	b.gt	.Ltrap
	add	x5, x3, x4
	cmp	x5, x0, lsl #16
	b.le	.Lno_trap

.Ltrap:
	mov	w0, #1
	b	.Lret

.Lno_trap:
	// Nothing to do?
	cbz	w4, .Lret_ok

	// Absolute addresses
	add	x0, x26, x2
	add	x1, x26, x3

	// Determine direction
	cmp	x1, x0
	b.ge	.Lforward

	// Move pointers to end
	add	x0, x0, x4
	add	x1, x1, x4

.Lbackward:
	ldrb	w2, [x1, #-1]!
	strb	w2, [x0, #-1]!
	subs	w4, w4, #1
	b.ne	.Lbackward

	b	.Lret_ok

.Lforward:
	ldrb	w2, [x1], #1
	strb	w2, [x0], #1
 	subs	w4, w4, #1
	b.ne	.Lforward

.Lret_ok:
	mov	w0, #0

.Lret:
	// Clear address
	mov	w1, #0
