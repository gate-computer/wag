#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef int32_t (*start_func)(void *text, void *rodata, void *, void *, void (*trap)(int));

struct header {
	uint64_t text_size;
	uint64_t rodata_size;
	uint64_t bss_size;
} __attribute__ ((packed));

static void *text_addr;

static void handle_signal(int signum, siginfo_t *i, void *context)
{
	fprintf(stderr, "exec: signal: signo     = %d (%s)\n", i->si_signo, strsignal(i->si_signo));
	fprintf(stderr, "exec: signal: errno     = %d\n", i->si_errno);
	fprintf(stderr, "exec: signal: code      = %d\n", i->si_code);
	fprintf(stderr, "exec: signal: pid       = %d\n", i->si_pid);
	fprintf(stderr, "exec: signal: uid       = %d\n", i->si_uid);
	fprintf(stderr, "exec: signal: status    = %d\n", i->si_status);
	fprintf(stderr, "exec: signal: utime     = %ld\n", i->si_utime);
	fprintf(stderr, "exec: signal: stime     = %ld\n", i->si_stime);
	fprintf(stderr, "exec: signal: value int = %d\n", i->si_value.sival_int);
	fprintf(stderr, "exec: signal: value ptr = %p\n", i->si_value.sival_ptr);
	fprintf(stderr, "exec: signal: int       = %d\n", i->si_int);
	fprintf(stderr, "exec: signal: ptr       = %p\n", i->si_ptr);
	fprintf(stderr, "exec: signal: overrun   = %d\n", i->si_overrun);
	fprintf(stderr, "exec: signal: timerid   = %d\n", i->si_timerid);
	fprintf(stderr, "exec: signal: addr      = %p (0x%lx)\n", i->si_addr, (void *) i->si_addr - text_addr);
	fprintf(stderr, "exec: signal: band      = %ld\n", i->si_band);
	fprintf(stderr, "exec: signal: fd        = %d\n", i->si_fd);
	fprintf(stderr, "exec: signal: addr_lsb  = %d\n", i->si_addr_lsb);
	fprintf(stderr, "exec: signal: call addr = %p (0x%lx)\n", i->si_call_addr, (void *) i->si_call_addr - text_addr);
	fprintf(stderr, "exec: signal: syscall   = %d\n", i->si_syscall);
	fprintf(stderr, "exec: signal: arch      = %u\n", i->si_arch);

	_exit(7);
}

static jmp_buf trap_buf;

static void handle_trap(int arg)
{
	fprintf(stderr, "exec: trap %d\n", arg);
	longjmp(trap_buf, 1);
}

static int32_t call(void *text, void *rodata, start_func start, int64_t arg, void (*trap)(int))
{
	register void *rdi asm ("rdi") = text;
	register void *rsi asm ("rsi") = rodata;
	register void *rdx asm ("rdx") = start;
	register int64_t rcx asm ("rcx") = arg;
	register void *r8 asm ("r8") = trap;

	int32_t retval;

	asm volatile (
		"        push    %%rcx  \n"
		"        call    *%%rdx \n"
		"        pop     %%rcx  \n"
		: "=a" (retval)
		: "r" (rdi), "r" (rsi), "r" (rdx), "r" (rcx), "r" (r8)
		: "cc", "memory"
	);

	return retval;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 1;

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		return 2;

	struct stat st;

	if (fstat(fd, &st) < 0)
		return 3;

	struct header head;

	if (lseek(fd, -sizeof (head), SEEK_END) < 0)
		return 4;

	if (read(fd, &head, sizeof (head)) != sizeof (head))
		return 5;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return 4;

	size_t data_size = st.st_size - head.text_size - head.rodata_size - sizeof (head);

	fprintf(stderr, "exec: text size   = %ld\n", head.text_size);
	fprintf(stderr, "exec: rodata size = %ld\n", head.rodata_size);
	fprintf(stderr, "exec: data size   = %ld\n", data_size);
	fprintf(stderr, "exec: bss size    = %ld\n", head.bss_size);

	size_t text_offset = 0;
	size_t rodata_offset = text_offset + head.text_size;
	size_t data_offset = rodata_offset + head.rodata_size;

	void *rodata_addr = NULL;
	void *data_addr = NULL;
	void *bss_addr = NULL;

	text_addr = mmap(NULL, head.text_size, PROT_EXEC|PROT_READ, MAP_PRIVATE|MAP_32BIT, fd, text_offset);
	if (text_addr == MAP_FAILED)
		return 6;

	fprintf(stderr, "exec: text addr   = %p\n", text_addr);

	if (head.rodata_size > 0) {
		rodata_addr = mmap(NULL, head.rodata_size, PROT_READ, MAP_PRIVATE|MAP_32BIT, fd, rodata_offset);
		if (rodata_addr == MAP_FAILED)
			return 6;
	}

	fprintf(stderr, "exec: rodata addr = %p\n", rodata_addr);

	if (data_size > 0) {
		data_addr = mmap(NULL, data_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_32BIT, fd, data_offset);
		if (data_addr == MAP_FAILED)
			return 6;
	}

	fprintf(stderr, "exec: data addr   = %p\n", data_addr);

	if (head.bss_size > 0) {
		bss_addr = mmap(NULL, head.bss_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_32BIT|MAP_ANONYMOUS, -1, 0);
		if (bss_addr == MAP_FAILED)
			return 6;
	}

	fprintf(stderr, "exec: bss addr    = %p\n", bss_addr);

	const struct sigaction signal_action = {
		.sa_sigaction = handle_signal,
		.sa_mask = 0,
		.sa_flags = SA_RESETHAND|SA_SIGINFO,
	};

	for (int signum = 1; signum < 32; signum++) {
		switch (signum) {
		case SIGKILL:
		case SIGCONT:
		case SIGSTOP:
			break;

		default:
			if (sigaction(signum, &signal_action, NULL) < 0)
				return 5;
		}
	}

	start_func start = (start_func) text_addr;

	bool fail = false;
	bool done = false;

	for (int id = 0; !done; id++) {
		int32_t assert_type = call(text_addr, rodata_addr, start, 0x100000 + id, handle_trap);
		if (assert_type < 0)
			break;

		if (setjmp(trap_buf)) {
			if (assert_type == 1) {
				fprintf(stderr, "exec: test #%d: trap ok\n", id);
			} else {
				fprintf(stderr, "exec: test #%d: failed due to unexpected trap\n", id);
				fail = true;
			}
			continue;
		}

		int32_t result = call(text_addr, rodata_addr, start, id, handle_trap);

		switch (result) {
		case 1:
			if (assert_type == 0) {
				fprintf(stderr, "exec: test #%d: return ok\n", id);
			} else {
				fprintf(stderr, "exec: test #%d: failed due to unexpected success\n", id);
				fail = true;
			}
			break;

		case 0:
			fprintf(stderr, "exec: test #%d: fail\n", id);
			fail = true;
			break;

		case -1:
			done = true;
			break;

		default:
			fprintf(stderr, "exec: test #%d: bad result: %d\n", id, result);
			fail = true;
			break;
		}
	}

	return fail ? 6 : 0;
}
