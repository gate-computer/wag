#include <stddef.h>

#include <sys/syscall.h>

static intptr_t syscall6(int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6)
{
	register uintptr_t x0 asm("x0") = a1;
	register uintptr_t x1 asm("x1") = a2;
	register uintptr_t x2 asm("x2") = a3;
	register uintptr_t x3 asm("x3") = a4;
	register uintptr_t x4 asm("x4") = a5;
	register uintptr_t x5 asm("x5") = a6;
	register int x8 asm("x8") = nr;

	asm volatile(
		"svc 0"
		: "+r"(x0)
		: "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
		: "cc", "memory");

	return x0;
}

static void (*get_sigsegv_handler(void))(int, siginfo_t *, void *)
{
	void (*retval)(int, siginfo_t *, void *);

	asm volatile(
		"          bl  .Lafter1 \n"
		""
		"          brk 0        \n" // TODO
		""
		".Lafter1: mov %0, x30  \n"
		: "=r"(retval)
		:
		: "x30");

	return retval;
}

static void (*get_signal_restorer(void))(void)
{
	void (*retval)(void);

	asm volatile(
		"          bl  .Lafter2 \n"
		""
		"          mov x8, 139  \n" // SYS_rt_sigreturn
		"          svc 0        \n"
		"          brk 0        \n"
		""
		".Lafter2: mov %0, x30  \n"
		: "=r"(retval)
		:
		: "x30");

	return retval;
}

NORETURN
static void start(void *text, void *memory_addr, void *stack_limit, void *stack_ptr, void *init_routine)
{
	register void *x1 asm("x1") = stack_limit - STACK_LIMIT_OFFSET + SIGNAL_STACK_OFFSET;
	register void *x2 asm("x2") = init_routine;
	register void *x26 asm("x26") = memory_addr;
	register void *x27 asm("x27") = text;
	register uintptr_t x28 asm("x28") = (uintptr_t) stack_limit >> 4;
	register void *x29 asm("x29") = stack_ptr;

	asm volatile(
		" mov sp, x1 \n" // real stack ptr
		" br  x2     \n" // exits via trap handler
		:
		: "r"(x1), "r"(x2), "r"(x26), "r"(x27), "r"(x28), "r"(x29)
		:);

	__builtin_unreachable();
}

static uint64_t begin_time(void)
{
	return 0; // TODO
}

static uint64_t end_time(void)
{
	return 0; // TODO
}
