// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#define __ASSEMBLY__

#include <asm/mman.h>
#include <asm/signal.h>
#include <linux/wait.h>
#include <sys/syscall.h>

#define SIGACT_FLAGS (SA_RESTART | SA_RESTORER | SA_SIGINFO)

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
	mov	$SYS_fork, %eax
	syscall
	mov	%rax, 8+104(%rsp)	// run func result
	test	%rax, %rax
	je	.Lchild
	jg	.Lparent
	ret

.Lparent:
	mov	%eax, %edi		// wait4 upid
	sub	$8, %rsp		// space for int
	mov	%rsp, %rsi		// wait4 stat_addr
	mov	$__WNOTHREAD, %rdx	// wait4 options
	sub	$144, %rsp		// sizeof (struct rusage)
	mov	%rsp, %r10		// wait4 ru
	mov	$SYS_wait4, %eax
	syscall
	add	$144, %rsp		// sizeof (struct rusage)
	add	$8, %rsp		// space for int
	mov	%rax, 8+104(%rsp)	// run func result
	ret

.Lchild:
	mov	$SIGSEGV, %edi		// sigaction signum
	sub	$32, %rsp		// sizeof (struct sigaction)
	mov	%rsp, %rsi		// sigaction act
	lea	sigsegv_handler(%rip), %rax
	mov	%rax, 0(%rsi)		// sa_handler
	movq	$SIGACT_FLAGS, 8(%rsi)	// sa_flags
	lea	signal_restorer(%rip), %rax
	mov	%rax, 16(%rsi)		// sa_restorer
	movq	$0, 24(%rsi)		// sa_mask
	xor	%edx, %edx		// sigaction oldact
	mov	$8, %r10d		// sigaction mask size
	mov	$SYS_rt_sigaction, %eax
	syscall
	add	$32, %rsp		// sizeof (struct sigaction)

	mov	8+0(%rsp), %r15		// run func param: text
	mov	8+32(%rsp), %r14	// run func param: memoryAddr
	mov	8+40(%rsp), %rbx	// run func param: stack
	mov	8+64(%rsp), %rcx	// run func param: stackOffset
	mov	8+72(%rsp), %rax	// run func param: initOffset
	mov	8+80(%rsp), %rdi	// run func param: slaveFd

	add	%rbx, %rcx		// stack ptr
	add	$128, %rbx		// for imports and traps
	add	$16, %rbx		// call + stack check trap call
	movq	%rdi, %mm6		// slave fd
	movq	%rsp, %mm7		// original stack
	mov	%rcx, %rsp		// stack ptr
	lea	(%rax, %r15), %rdi	// init routine
	jmp	*%rdi			// exits via trap handler

.align	16
.global	resume

resume:
	lea	16(%r15), %rdi		// resume routine
	jmp	*%rdi

.align	16
.global	sigsegv_handler

sigsegv_handler:
	mov	160(%rdx), %rax		// rsp in ucontext
	sub	$8, %rax
	mov	%rax, 160(%rdx)		// rsp in ucontext

	mov	168(%rdx), %rbx		// rip in ucontext
	mov	%rbx, (%rax)

	lea	.Lsigsegv_exit(%rip), %rbx
	mov	%rbx, 168(%rdx)		// rip in ucontext
	ret

.Lsigsegv_exit:
	mov	$5, %eax		// MemoryAccessOutOfBounds
	jmp	trap_handler

.align	16
.global	signal_restorer

signal_restorer:
	mov	$SYS_rt_sigreturn, %eax
	syscall
	hlt

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

	mov	8+96(%rsp), %edi	// run func param: resultFd -> write fd

	sub	$24, %rsp		// sizeof result
	mov	%rsp, %rsi		// write buf
	mov	%rax, 0(%rsi)		// result: TrapID
	mov	-24(%r15), %r13d	// current memory pages
	shl	$16, %r13
	mov	%r13, 8(%rsi)		// result: MemorySize
	mov	%r11, 16(%rsi)		// result: StackPtr
	mov	$24, %edx		// write count
	mov	$SYS_write, %eax
	syscall
	add	$24, %rsp		// sizeof result

	xor	%edi, %edi		// exit status
	mov	$SYS_exit_group, %eax	// child process
	syscall
	hlt

.Lpause:
	push	%rcx
	push	%rsi
	push	%rsi
	push	%r11

	mov	$SYS_write, %eax
	movq	%mm6, %rdi		// fd
	lea	-8(%rsp), %rsi		// buf
	movq	$-2, (%rsi)		// buf content
	mov	$8, %edx		// bufsize
	syscall
	sub	%rdx, %rax
	jne	.Lfail_trap

	mov	$SYS_read, %eax
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
.global	grow_memory

grow_memory:
	mov	%eax, %r12d

	mov	-24(%r15), %edi		// current memory pages
	add	%rdi, %r12		// new memory pages
	cmp	%r12, -32(%r15)		// grow memory limit pages
	jl	.Loom

	shl	$16, %rdi		// current memory bytes
	add	%r14, %rdi		// mprotect addr

	mov	%eax, %esi
	shl	$16, %rsi		// mprotect len
	je	.Lgrow_done

	mov	$PROT_READ|PROT_WRITE, %edx
	mov	$SYS_mprotect, %eax
	syscall
	test	%rax, %rax
	je	.Lgrow_done

	mov	$3005, %eax
	jmp	trap_handler

.Lgrow_done:
	mov	-24(%r15), %eax		// old memory pages
	mov	%r12d, -24(%r15)	// new memory pages
	jmp	resume

.Loom:
	mov	$-1, %eax
	jmp	resume

.align	16
.global	spectest_print

spectest_print:
	mov	(%rsp), %r9		// save link address

	mov	$SYS_write, %eax
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
	mov	%r8, %rax
	add	%r9, %rax		// absolute addr+size

	movq	%mm6, %rdi		// fd
	lea	-12(%rsp), %rsi		// buf
	mov	$12, %edx		// bufsize

	movq	$-3, (%rsi)		// command
	mov	%r9d, 8(%rsi)		// size

	mov	$SYS_write, %eax
	syscall
	cmp	%rdx, %rax
	jne	.Lfail_putns3

	mov	%r8, %rsi		// buf <- absolute addr
	mov	%r9d, %edx		// bufsize <- size

	mov	$SYS_write, %eax
	syscall
	cmp	%rdx, %rax
	jne	.Lfail_putns4

	xor	%eax, %eax
	jmp	resume

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
	mov	8+88(%rax), %rax	// run func param: arg
	jmp	resume

.align	16
.global	snapshot

snapshot:
	sub	$8, %rsp		// bufsize

	mov	$SYS_write, %eax
	movq	%mm6, %rdi 		// fd
	mov	%rsp, %rsi		// buf
	movq	$-1, (%rsi)		// buf contents
	mov	$8, %edx		// bufsize
	syscall
	sub	%rdx, %rax
	jne	.Lfail_snapshot

	mov	$SYS_write, %eax
	mov	-24(%r15), %r13d	// current memory pages
	shl	$16, %r13
	add	%r14, %r13		// current memory end address
	mov	%r13, (%rsi)		// buf contents
	syscall
	sub	%rdx, %rax
	jne	.Lfail_snapshot

	mov	$SYS_write, %eax
	mov	%rsp, %r13
	add	$8, %r13		// stack ptr before snapshot call
	mov	%r13, (%rsi)		// buf contents
	syscall
	sub	%rdx, %rax
	jne	.Lfail_snapshot

	mov	$SYS_read, %eax
	syscall
	sub	%rdx, %rax
	jne	.Lfail_snapshot
	mov	(%rsi), %rax		// snapshot id

	add	$8, %rsp		// bufsize

	jmp	resume

.Lfail_snapshot:
	add	$8, %rsp		// bufsize

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
