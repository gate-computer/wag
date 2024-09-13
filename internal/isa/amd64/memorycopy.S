// Copyright (c) 2024 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

.intel_syntax noprefix

.globl _start

// Input:
//	[rsp+24]: target address within wasm memory (32-bit)
//	[rsp+16]: source address within wasm memory (32-bit)
//	[rsp+8]:  region length (32-bit)
//	eax:      wasm memory pages
//	r14:      wasm memory address
//
// Output:
//	ZF=0 causes trap
//
// Must be preserved:
//	rbx
//	r14
//	r15

_start:
	// Arguments
	mov	ebp, [rsp+24]
	mov	esi, [rsp+16]
	mov	edi, [rsp+8]

	// Wasm memory bytes
	shl	eax, 16

	// Bounds checks
	sub	rax, rdi
	cmp	rax, rbp
	jl	.Ltrap
	cmp	rax, rsi
	jge	.Lno_trap

.Ltrap:
	// Clear zero flag
	test	rsp, rsp
	jmp	.Lret

.Lno_trap:
	// Nothing to do?
	test	edi, edi
	jz	.Lret

	// Absolute addresses
	add	rbp, r14
	add	rsi, r14

	// Determine direction
	cmp	rsi, rbp
	jge	.Lforward

	// Move pointers to end
	add	rbp, rdi
	add	rsi, rdi

.Lbackward:
	dec	rsi
	mov	dl, [rsi]
	dec	rbp
	mov	[rbp], dl
	dec	rdi
	jnz	.Lbackward

	jmp	.Lret

.Lforward:
	mov	dl, [rsi]
	inc	rsi
	mov	[rbp], dl
	inc	rbp
	dec	rdi
	jnz	.Lforward

.Lret:
