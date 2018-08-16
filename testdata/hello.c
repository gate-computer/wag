// clang --target=wasm32 -Oz -nostdlib -Wl,--allow-undefined -Wl,--no-entry -Wl,--export=main -o hello.wasm hello.c

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
	const char *hello = "hello, ";
	const char *world = "world\n";

	if (write(STDOUT_FILENO, hello, strlen(hello)) != strlen(hello))
		return 1;

	char buf[128];

	for (int i = 0; i < sizeof buf; i++)
		buf[i] = i;

	int zero = open("/dev/zero", O_RDONLY);
	if (zero < 0)
		return 1;

	if (read(zero, buf, sizeof buf) != sizeof buf)
		return 1;

	if (close(zero) != 0)
		return 1;

	for (int i = 0; i < sizeof buf; i++)
		if (buf[i] != 0)
			return 1;

	int fds[2];

	if (pipe2(fds, O_CLOEXEC) < 0)
		return 1;

	if (close(fds[0]) != 0)
		return 1;

	if (close(fds[1]) != 0)
		return 1;

	int out = open("/dev/stdout", O_WRONLY);
	if (out < 0)
		return 1;

	if (write(out, world, strlen(world)) != strlen(world))
		return 1;

	if (close(out) != 0)
		return 1;

	if (close(STDIN_FILENO) != 0)
		return 1;

	if (close(STDOUT_FILENO) != 0)
		return 1;

	if (close(STDERR_FILENO) != 0)
		return 1;

	if (close(STDERR_FILENO) == 0)
		return 1;

	_exit(0);
	return 1;
}
