#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAGIC   0x54fd3985
#define ID_BASE 556231

typedef int32_t (*start_func)(void);

static void *start_addr;

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
	fprintf(stderr, "exec: signal: addr      = %p (0x%lx)\n", i->si_addr, (void *) i->si_addr - start_addr);
	fprintf(stderr, "exec: signal: band      = %ld\n", i->si_band);
	fprintf(stderr, "exec: signal: fd        = %d\n", i->si_fd);
	fprintf(stderr, "exec: signal: addr_lsb  = %d\n", i->si_addr_lsb);
	fprintf(stderr, "exec: signal: call addr = %p (0x%lx)\n", i->si_call_addr, (void *) i->si_call_addr - start_addr);
	fprintf(stderr, "exec: signal: syscall   = %d\n", i->si_syscall);
	fprintf(stderr, "exec: signal: arch      = %u\n", i->si_arch);

	_exit(6);
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

	start_addr = mmap(NULL, st.st_size, PROT_EXEC|PROT_READ, MAP_PRIVATE, fd, 0);
	if (start_addr == MAP_FAILED)
		return 4;

	fprintf(stderr, "exec: start = 0x%p\n", start_addr);

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

	start_func start = (start_func) start_addr;

	int32_t result = start();
	if (result != MAGIC) {
		fprintf(stderr, "exec: failed test: %d\n", result - ID_BASE);
		return 6;
	}

	fprintf(stderr, "exec: ok\n");
	return 0;
}
