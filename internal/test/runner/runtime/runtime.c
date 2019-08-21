#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>

#include <linux/wait.h>

#define NORETURN __attribute__((noreturn))

#define SYS_SA_RESTORER 0x04000000

#define STACK_CHECK_SPACE 16
#define STACK_LIMIT_OFFSET (16 + 8000 + 128 + STACK_CHECK_SPACE) // vars + signal stack + red zone

struct state {
	int64_t arg;
	int slave_fd;
	int result_fd;
};

static intptr_t syscall6(int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6);
static void (*get_sigsegv_handler(void))(int, siginfo_t *, void *);
static void (*get_signal_restorer(void))(void);
NORETURN static void start(void *text, void *memory_addr, void *stack_limit, void *stack_ptr, void *init_routine);
static uint64_t begin_time(void);
static uint64_t end_time(void);

#include "runtime.h"

static intptr_t syscall4(int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
	return syscall6(nr, a1, a2, a3, a4, 0, 0);
}

static intptr_t syscall3(int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3)
{
	return syscall4(nr, a1, a2, a3, 0);
}

static intptr_t syscall1(int nr, uintptr_t a1)
{
	return syscall3(nr, a1, 0, 0);
}

NORETURN
static void sys_exit_group(int status)
{
	syscall1(SYS_exit_group, status);
	__builtin_unreachable();
}

static intptr_t sys_fork(void)
{
	return syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
}

static intptr_t sys_mprotect(void *addr, size_t len, int prot)
{
	return syscall3(SYS_mprotect, (uintptr_t) addr, len, prot);
}

static intptr_t sys_read(int fd, void *buf, size_t count)
{
	return syscall3(SYS_read, fd, (uintptr_t) buf, count);
}

static intptr_t sys_sigaction(int signum, void (*sigaction)(int, siginfo_t *, void *), int flags)
{
	const uint64_t buf[4] = {
		(uintptr_t) sigaction,
		flags | SYS_SA_RESTORER | SA_SIGINFO,
		(uintptr_t) get_signal_restorer(),
		0,
	};
	return syscall4(SYS_rt_sigaction, signum, (uintptr_t) buf, 0, 8);
}

static intptr_t sys_wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage)
{
	return syscall4(SYS_wait4, pid, (uintptr_t) wstatus, options, (uintptr_t) rusage);
}

static intptr_t sys_write(int fd, const void *buf, size_t count)
{
	return syscall3(SYS_write, fd, (uintptr_t) buf, count);
}

int run(void *text, void *memory_addr, void *stack, int stack_offset, int init_offset, int slave_fd, int64_t arg, int result_fd, struct state *state)
{
	int child_pid = sys_fork();
	if (child_pid == 0) {
		state->arg = arg;
		state->slave_fd = slave_fd;
		state->result_fd = result_fd;

		for (int sig = 1; sig <= 64; sig++)
			switch (sig) {
			case SIGKILL:
			case SIGSEGV:
			case SIGSTOP:
				break;

			default:
				if (sys_sigaction(sig, NULL, 0) != 0)
					sys_exit_group(1);
			}

		if (sys_sigaction(SIGSEGV, get_sigsegv_handler(), SA_RESTART) != 0)
			sys_exit_group(1);

		start(text, memory_addr, stack + STACK_LIMIT_OFFSET, stack + stack_offset, text + init_offset);
	} else if (child_pid > 0) {
		int status;
		struct rusage rusage;

		int ret = sys_wait4(child_pid, &status, __WNOTHREAD, &rusage);
		if (ret < 0)
			return ret;

		return status;
	} else {
		return child_pid;
	}
}

static void handle_trap(uintptr_t stack_limit, void *stack_ptr, uint64_t trap, struct state *state)
{
	if (trap == 1) { // NoFunction
		uint64_t cmd = -2;
		uint8_t res;
		if (sys_write(state->slave_fd, &cmd, sizeof cmd) == sizeof cmd &&
		    sys_read(state->slave_fd, &res, sizeof res) == sizeof res)
			return; // resume program

		trap = 3003; // failure
	}

	if (trap == 3 && (stack_limit & 1) == 1) { // CallStackExhausted due to suspension
		stack_limit &= 0x7ffffffffffffffeULL;
		trap = 1; // Suspended
	}

	void *stack = (void *) stack_limit - STACK_LIMIT_OFFSET;

	const uint64_t buf[3] = {
		trap,
		*(uint32_t *) stack << 16, // current memory size
		(uint64_t) stack_ptr,
	};
	sys_write(state->result_fd, buf, sizeof buf);

	sys_exit_group(0);
}

void trap_handler(uintptr_t stack_limit, void *stack_ptr, uint64_t trap, struct state *state)
{
	handle_trap(stack_limit, stack_ptr, trap, state);
}

static inline unsigned int get_current_memory(void *stack_limit)
{
	void *stack = (void *) stack_limit - STACK_LIMIT_OFFSET;
	return *(uint32_t *) stack;
}

unsigned int current_memory(void *stack_limit)
{
	return get_current_memory(stack_limit);
}

unsigned int grow_memory(void *stack_limit, void *memory_addr, void *text, unsigned int grow_pages)
{
	void *stack = (void *) stack_limit - STACK_LIMIT_OFFSET;
	unsigned int grow_limit = *(uint64_t *) (text - 32);
	unsigned int old_pages = *(uint32_t *) stack;
	uint64_t new_pages = (uint64_t) old_pages + (uint64_t) grow_pages;

	if (new_pages > grow_limit)
		return -1;

	if (sys_mprotect(memory_addr + (old_pages << 16), grow_pages << 16, PROT_READ | PROT_WRITE) != 0)
		sys_exit_group(1);

	*(uint32_t *) stack = new_pages;
	return old_pages;
}

void spectest_print(uint64_t info, const uint64_t *args, struct state *state)
{
	uint32_t argcount = info >> 32;
	ssize_t argsize = argcount * sizeof(uint64_t);
	uint64_t sigindex = info & 0xffffffff;

	if (sys_write(state->slave_fd, &sigindex, sizeof sigindex) != sizeof sigindex)
		sys_exit_group(1);

	if (sys_write(state->slave_fd, args, argsize) != argsize)
		sys_exit_group(1);
}

void putns(void)
{
	// TODO
}

uint64_t benchmark_begin(void)
{
	return begin_time();
}

uint64_t benchmark_end(uint64_t begin)
{
	uint64_t diff = end_time() - begin;
	if (diff >= 0x80000000)
		diff = -1;
	return diff;
}

int64_t get_arg(struct state *state)
{
	return state->arg;
}

uint64_t snapshot(void *stack_limit, void *stack_ptr, void *memory_addr, struct state *state)
{
	void *memory_end = memory_addr + ((uintptr_t) get_current_memory(stack_limit) << 16);

	const uint64_t buf[3] = {
		-1, // command
		(uintptr_t) memory_end,
		(uintptr_t) stack_ptr,
	};

	if (sys_write(state->slave_fd, buf, sizeof buf) != sizeof buf)
		sys_exit_group(1);

	uint64_t res;

	if (sys_read(state->slave_fd, &res, sizeof res) != sizeof res)
		sys_exit_group(1);

	return res;
}
