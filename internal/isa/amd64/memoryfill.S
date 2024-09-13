// Copyright (c) 2024 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

.intel_syntax noprefix

.globl _start

// Input:
//	[rsp + 24]: target address within wasm memory (32-bit)
//	[rsp + 16]: value (8-bit)
//	[rsp + 8]:  region length (32-bit)
//	eax:        wasm memory pages
//	r14:        wasm memory address
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
	mov	ebp, [rsp + 24]
	mov	sil, [rsp + 16]
	mov	edi, [rsp + 8]

	// Wasm memory bytes
	shl	eax, 16

	// Target bounds check
	sub	rax, rbp
	cmp	rax, rdi
	jge	.Lno_trap

	// Trap (clear zero flag)
	test	rsp, rsp
	jmp	.Lret

.Lno_trap:
	// Nothing to do?
	test	edi, edi
	jz	.Lret

	// Absolute address
	add	rbp, r14

.Lloop:
	mov	[rbp], sil
	inc	rbp
	dec	edi
	jnz	.Lloop

.Lret:
