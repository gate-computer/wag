#include <stddef.h>

#include <sys/syscall.h>

static void handle_trap(uintptr_t stack_limit, void *stack_ptr, uint64_t trap, struct state *state);

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
		"          bl      .Lafter1        \n"
		""
		""         // start of sigsegv handler
		"          ldr     x0, [x2, #416]  \n" // x29 in ucontext
		"          sub     x0, x0, #8      \n"
		"          str     x0, [x2, #416]  \n" // x29 in ucontext
		"          ldr     x1, [x2, #440]  \n" // pc in ucontext
		"          str     x1, [x0]        \n"
		"          mov     x0, x30         \n"
		"          bl      .Lafter3        \n"
		""
		""         // start of sigsegv exit routine
		"          lsl     x0, x28, #4     \n"
		"          mov     x1, x29         \n"
		"          mov     x2, #5          \n"
		"          mov     x3, #12032      \n" // STACK_LIMIT_OFFSET - STACK_FOR_RT_CALLS
		"          sub     x3, sp, x3      \n" // start of stack
		"          ldr     x3, [x3, #8]    \n" // state ptr in vars
		"          b       handle_trap     \n"
		""         // end of sigsegv exit routine
		""
		".Lafter3: str     x30, [x2, #440] \n" // pc in ucontext
		"          ret     x0              \n"
		""         // end of sigsegv handler
		""
		".Lafter1: mov     %0, x30         \n"
		: "=r"(retval)
		:
		: "x30");

	return retval;
}

static void (*get_signal_restorer(void))(void)
{
	void (*retval)(void);

	asm volatile(
		"          bl      .Lafter2 \n"
		""
		"          mov     x8, 139  \n" // SYS_rt_sigreturn
		"          svc     0        \n"
		"          brk     0        \n"
		""
		".Lafter2: mov     %0, x30  \n"
		: "=r"(retval)
		:
		: "x30");

	return retval;
}

NORETURN
static void start(void *text, void *stack_limit, void *stack_ptr, void *init_routine)
{
	uintptr_t link_ptr = 0;
	if (((uintptr_t) init_routine & 0x7f) == 0x20) { // resume routine
		link_ptr = *(uintptr_t *) stack_ptr;
		stack_ptr += sizeof(uintptr_t);
	}

	register uintptr_t x0 asm("x0") = (uintptr_t) stack_limit - STACK_FOR_RT_CALLS;
	register void *x1 asm("x1") = init_routine;
	register void *x27 asm("x27") = text;
	register uintptr_t x28 asm("x28") = (uintptr_t) stack_limit >> 4;
	register void *x29 asm("x29") = stack_ptr;
	register uintptr_t x30 asm("x30") = link_ptr;

	asm volatile(
		" mov sp, x0 \n" // real stack ptr
		" br  x1     \n" // exits via trap handler
		:
		: "r"(x0), "r"(x1), "r"(x27), "r"(x28), "r"(x29), "r"(x30)
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
