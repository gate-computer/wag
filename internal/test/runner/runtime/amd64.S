// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

.text

.align	16
.global	object_runtime_start

object_runtime_start:
	mov	$0x300000000, %rax
	mov	(%rax), %rcx		// stack frame size
	add	%rcx, %rax		// at last item of stack frame data
	shr	$3, %rcx		// stack item count
	je	.Lnocopy

.Lcopy:
	mov	(%rax), %rbx
	sub	$8, %rax
	push	%rbx
	loop	.Lcopy			// decrement rcx and jump if not zero

.Lnocopy:
	xor	%eax, %eax		// resume
	mov	%rsp, %rbx		// stack ptr
	mov	$0x100000, %rcx		// stack offset
	sub	%rbx, %rbx		// stack limit
	xor	%edx, %edx		// arg
	mov	$1023, %edi		// slave fd
	mov	$0x1000000, %r13	// init memory size
	mov	$0x400000000, %r14	// memory
	mov	$0x200000000, %r15	// text

	sub	$256, %rsp		// space for args and results
	call	run

	mov	$0, %edi		// exit status
	mov	$231, %eax		// exit_group syscall
	syscall
	hlt

.align	16
.global	run

run:
	add	%r14, %r13		// current memory limit
	add	%rbx, %rcx		// stack ptr
	add	$128, %rbx		// for imports and traps
	add	$16, %rbx		// call + stack check trap call
	movq	%rdi, %mm6		// slave fd
	push	%rdx			// arg
	movq	%rsp, %mm7		// original stack
	mov	%rcx, %rsp		// stack ptr
	lea	16(%r15), %rdi		// resume routine
	test	%rax, %rax
	jne	.Lresume
	add	$16, %rdi		// init routine
.Lresume:
	jmp	*%rdi			// returns via trap handler

.align	16
.global	resume

resume:
 	lea	16(%r15), %rdi		// resume routine
 	jmp	*%rdi

.align	16
.global	trap_handler

trap_handler:
	cmp	$3, %eax		// CallStackExhausted
	jne	.Lskip
	test	$1, %bl
	je	.Lskip
	mov	$2, %eax		// Suspended
.Lskip:
	cmp	$1, %eax		// NoFunction
	je	.Lpause

	mov	%rsp, %r11		// stack ptr
	movq	%mm7, %rsp		// original stack
	add	$8, %rsp		// arg
	mov	%rax, 8+96(%rsp)	// run func param: trapID
	sub	%r14, %r13
	mov	%r13, 8+104(%rsp)	// run func param: currentMemorySize
	mov	%r11, 8+112(%rsp)	// run func param: stackPtr
	ret				// return from run func

.Lpause:
	push	%rcx
	push	%rsi
	push	%rsi
	push	%r11

	mov	$1, %eax		// sys_write
	movq	%mm6, %rdi		// fd
	lea	-8(%rsp), %rsi		// buf
	movq	$-2, (%rsi)		// buf content
	mov	$8, %edx		// bufsize
	syscall
	sub	%rdx, %rax
	jne	.Lfail_trap

	xor	%eax, %eax		// sys_read
	mov	$1, %edx		// bufsize
	syscall
	sub	%rdx, %rax
	jne	.Lfail_trap

	pop	%r11
	pop	%rdi
	pop	%rsi
	pop	%rcx

	subq	$5, (%rsp)		// move return address before the call that got us here
	jmp	resume

.Lfail_trap:
	mov	$3003, %rax
	jmp	trap_handler

.align	16
.global	spectest_print

spectest_print:
	mov	(%rsp), %r9		// save link address

	mov	$1, %eax		// sys_write
	movq	%mm6, %rdi		// fd
	mov	%rbp, %rdx		// (argcount << 32) | sigindex
	shr	$32, %rdx		// argcount
	inc	%edx			// 1 + argcount
	shl	$3, %edx		// (1 + argcount) * wordsize = bufsize
	mov	%rsp, %rsi		// buf
	mov	%ebp, %ebp		// sigindex
	mov	%rbp, (%rsi)		// write sigindex before args (replace link address)
	syscall
	sub	%rdx, %rax
	jne	.Lfail_print

	mov	%r9, (%rsp)		// restore link address
	xor	%eax, %eax
	jmp	resume

.Lfail_print:
	mov	$3001, %rax
	jmp	trap_handler

.align	16
.global	putns

putns:
	mov	16(%rsp), %r8		// relative addr
	mov	8(%rsp), %r9		// size

	add	%r14, %r8		// absolute addr
	cmp	%r8, %r14
	jg	.Lfail_putns1		// absolute addr out of lower bound

	mov	%r8, %rax
	add	%r9, %rax		// absolute addr+size
	cmp	%rax, %r13
	jle	.Lfail_putns2		// absolute addr+size out of upper bound

	movq	%mm6, %rdi		// fd
	lea	-12(%rsp), %rsi		// buf
	mov	$12, %edx		// bufsize

	movq	$-3, (%rsi)		// command
	mov	%r9d, 8(%rsi)		// size

	mov	$1, %eax		// sys_write
	syscall
	cmp	%rdx, %rax
	jne	.Lfail_putns3

	mov	%r8, %rsi		// buf <- absolute addr
	mov	%r9d, %edx		// bufsize <- size

	mov	$1, %eax		// sys_write
	syscall
	cmp	%rdx, %rax
	jne	.Lfail_putns4

	xor	%eax, %eax
	jmp	resume

.Lfail_putns1:
	mov	$3001, %rax
	jmp	trap_handler

.Lfail_putns2:
	mov	$3002, %rax
	jmp	trap_handler

.Lfail_putns3:
	mov	$3003, %rax
	jmp	trap_handler

.Lfail_putns4:
	mov	$3004, %rax
	jmp	trap_handler

.align	16
.global	benchmark_begin

benchmark_begin:
	mov	%rbx, %r9

	cpuid				// serialize
	rdtsc
	shl	$32, %rdx
	or	%rdx, %rax

	mov	%r9, %rbx
	jmp	resume

.align	16
.global	benchmark_end

benchmark_end:
	mov	%rbx, %r9

	rdtsc
	shl	$32, %rdx
	or	%rdx, %rax
	sub	8(%rsp), %rax
	mov	$-1, %edx
	mov	$0x80000000, %ecx
	cmp	%rax, %rcx
	cmovle	%edx, %eax

	mov	%r9, %rbx
	jmp	resume

.align	16
.global	benchmark_barrier

benchmark_barrier:
	mov	16(%rsp), %rax
	jmp	resume

.align	16
.global	get_arg

get_arg:
	movq	%mm7, %rax		// original stack
	mov	(%rax), %rax		// arg
	jmp	resume

.align	16
.global	snapshot

snapshot:
	mov	$1, %eax		// sys_write
	movq	%mm6, %rdi 		// fd
	lea	-8(%rsp), %rsi		// buf
	movq	$-1, (%rsi)		// buf contents
	mov	$8, %edx		// bufsize
	syscall
	sub	%rdx, %rax
	jne	.Lfail_snapshot

	mov	$1, %eax		// sys_write
	mov	%r13, (%rsi)		// buf contents
	syscall
	sub	%rdx, %rax
	jne	.Lfail_snapshot

	mov	$1, %eax		// sys_write
	mov	%rsp, (%rsi)		// buf contents
	syscall
	sub	%rdx, %rax
	jne	.Lfail_snapshot

	xor	%eax, %eax		// sys_read
	syscall
	sub	%rdx, %rax
	jne	.Lfail_snapshot
	mov	(%rsi), %rax		// snapshot id

	jmp	resume

.Lfail_snapshot:
	mov	$3002, %rax
	jmp	trap_handler

.align	16
.global	suspend_next_call

suspend_next_call:
	mov	$-8, %rbx		// even value doesn't suspend loops
	jmp	resume

.align	16
.global	object_runtime_end

object_runtime_end:
