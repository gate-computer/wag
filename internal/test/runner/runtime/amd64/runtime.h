#include <stddef.h>

#include <sys/syscall.h>

void sigsegv_handler(int, siginfo_t *, void *);
void signal_restorer(void);

static intptr_t syscall6(int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6)
{
	intptr_t retval;
	register uintptr_t rdi asm("rdi") = a1;
	register uintptr_t rsi asm("rsi") = a2;
	register uintptr_t rdx asm("rdx") = a3;
	register uintptr_t r10 asm("r10") = a4;
	register uintptr_t r8 asm("r8") = a5;
	register uintptr_t r9 asm("r9") = a6;

	asm volatile(
		"syscall"
		: "=a"(retval)
		: "a"(nr), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
		: "cc", "rcx", "r11", "memory");

	return retval;
}

static void (*get_sigsegv_handler(void))(int, siginfo_t *, void *)
{
	return sigsegv_handler;
}

static void (*get_signal_restorer(void))(void)
{
	return signal_restorer;
}

NORETURN
static void start(void *text, void *memory_addr, void *stack_limit, void *stack_ptr, void *init_routine)
{
	register void *rcx asm("rcx") = stack_ptr;
	register void *rbx asm("rbx") = stack_limit;
	register void *rdi asm("rdi") = init_routine;
	register void *r14 asm("r14") = memory_addr;
	register void *r15 asm("r15") = text;

	asm volatile(
		" mov %%rcx, %%rsp \n" // stack ptr
		" jmp *%%rdi       \n" // exits via trap handler
		:
		: "r"(rcx), "r"(rbx), "r"(rdi), "r"(r14), "r"(r15)
		:);

	__builtin_unreachable();
}

static uint64_t begin_time(void)
{
	asm volatile(
		" xor   %%rax, %%rax \n"
		" cpuid              \n" // serialize
		:
		:
		: "cc", "rax", "rbx", "rcx", "rdx");

	return end_time();
}

static uint64_t end_time(void)
{
	uint64_t retval;

	asm volatile(
		" rdtsc              \n"
		" shl   $32, %%rdx   \n"
		" or    %%rdx, %%rax \n"
		: "=a"(retval)
		:
		: "cc", "rdx");

	return retval;
}
