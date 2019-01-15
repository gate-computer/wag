// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

.text

.global	object_runtime_start

link_object_runtime_start:
	bl	.Lafter_object_runtime_start

	mov	x0, 0			// resume result
	mov	x1, 0x80000000		// grow memory size
	mov	x3, 0x100000		// stack offset
	sub	x2, sp, x3		// stack limit
	mov	x4, 1023		// slave fd
	mov	x5, 0			// arg
	mov	x7, 0x1000000		// init memory size
	mov	x26, 0x300000000	// memory
	mov	x27, 0x200000000	// text

	sub	sp, sp, 256		// space for args and results
	bl	run

	mov	x0, 0			// exit status
	mov	x8, 94			// exit_group syscall
	svc	0
	brk	0

.Lafter_object_runtime_start:
	ret

.global	run

run:
	dsb	0xf
	isb	0xf

	add	x25, x26, x7		// current memory limit

	add	x29, x2, x3		// fake stack ptr
	mov	x6, sp
	mov	sp, x2			// real stack ptr

	str	x5, [sp, 0]		// arg
	str	x4, [sp, 8]		// slave fd
	str	x28, [sp, 16]		// Go 'g'
	str	x6, [sp, 24]		// original stack ptr
	add	x2, x2, 32

	add	x2, x2, 128		// for imports and traps
	add	x2, x2, 16		// call + stack check trap call
	lsr	x2, x2, 4
	mov	x28, x2			// stack limit / 16

	mov	x1, x27
	add	x1, x1, 16		// resume routine
	cbnz	x0, .Lresume
	add	x1, x1, 16		// init routine
.Lresume:
	br	x1			// returns via trap handler

.global	import_trap_handler

import_trap_handler:
	bl	.Lafter_trap_handler

	cmp	x0, 3			// CallStackExhausted
	bne	.Lnosusp
	tbnz	x28, 0, .Lnosusp
	mov	x0, 2			// Suspended

.Lnosusp:
	cmp	x0, 1			// NoFunction
	beq	.Lpause

.Lreturn:
	ldr	x28, [sp, 16]
	ldr	x6, [sp, 24]		// original stack ptr
	mov	sp, x6

	str	x0, [sp, 8+112]		// run func param: trapID
	sub	x25, x25, x26
	str	x25, [sp, 8+120]	// run func param: currentMemorySize
	str	x29, [sp, 8+128]	// run func param: trapID: stackPtr
	ret

.Lpause:
	mov	x8, 64			// sys_write
	ldr	x0, [sp, 8]		// fd
	mov	x1, x29
	sub	x1, x1, 8		// buf
	mov	x3, -2
	str	x3, [x1]		// buf content
	mov	x2, 8			// bufsize
	svc	0
	sub	x0, x0, x2
	bne	.Lfail_trap

	mov	x8, 63			// sys_read
	ldr	x0, [sp, 8]		// fd
	mov	x2, 1			// bufsize
	svc	0
	sub	x0, x0, x2
	bne	.Lfail_trap

	sub	x30, x30, 4		// move return address before the call that got us here
	b	resume

.Lfail_trap:
	mov	x0, 3003
	ldr	x1, [x29, -16]		// trap handler
	br	x1			// trap

.Lafter_trap_handler:
	str	x30, [sp, 8]
	ret

.global	import_grow_memory

import_grow_memory:
	bl	.Lafter_grow_memory

	b	resume

.Lafter_grow_memory:
	str	x30, [sp, 8]
	ret

.global	resume

resume:
	add	x1, x27, 16		// resume routine
	br	x1

.global	import_spectest_print

import_spectest_print:
	bl	.Lafter_spectest_print

	mov	x8, 64			// sys_write
	str	x0, [sp, 8]		// fd
	mov	x3, x2			// (argcount << 32) | sigindex
	lsr	x2, x2, 32		// argcount
	add	x2, x2, 1		// 1 + argcount
	lsl	x2, x2, 3		// (1 + argcount) * wordsize = bufsize
	mov	x1, x29
	sub	x1, x1, 8		// buf
	lsr	w3, w3, 0		// sigindex
	str	x3, [x1]		// write sigindex before args
	svc	0
	subs	x0, x0, x2
	bne	.Lfail_spectest_print
	b	resume

.Lfail_spectest_print:
	mov	x0, 3001
	ldr	x1, [x29, -16]		// trap handler
	b	x1			// trap

.Lafter_spectest_print:
	str	x30, [sp, 8]
	ret

.global	import_putns

import_putns:
	bl	.Lafter_putns

	brk	0
	b	resume

.Lafter_putns:
	str	x30, [sp, 8]
	ret

.global	import_benchmark_begin

import_benchmark_begin:
	bl	.Lafter_benchmark_begin

	brk	0
	b	resume

.Lafter_benchmark_begin:
	str	x30, [sp, 8]
	ret

.global	import_benchmark_end

import_benchmark_end:
	bl	.Lafter_benchmark_end

	brk	0
	b	resume

.Lafter_benchmark_end:
	str	x30, [sp, 8]
	ret

.global	import_benchmark_barrier

import_benchmark_barrier:
	bl	.Lafter_benchmark_barrier

	brk	0
	b	resume

.Lafter_benchmark_barrier:
	str	x30, [sp, 8]
	ret

.global	import_get_arg

import_get_arg:
	bl	.Lafter_get_arg

	brk	0
	b	resume

.Lafter_get_arg:
	str	x30, [sp, 8]
	ret

.global	import_snapshot

import_snapshot:
	bl	.Lafter_snapshot

	brk	0
	b	resume

.Lafter_snapshot:
	str	x30, [sp, 8]
	ret

.global	import_suspend_next_call

import_suspend_next_call:
	bl	.Lafter_suspend_next_call

	brk	0
	b	resume

.Lafter_suspend_next_call:
	str	x30, [sp, 8]
	ret

.global	object_runtime_end

link_object_runtime_end:
	ret
