#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAGIC 0x54fd3985

typedef int32_t (*start_func)(void);

const int32_t ref = ((int32_t) 1 + (int32_t) 2) + ((int32_t) 0x7fffffff + (int32_t) 3);

int main(int argc, char **argv)
{
	if (argc != 2)
		return 1;

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		return 2;

	void *ptr = mmap(NULL, 4096, PROT_EXEC|PROT_READ, MAP_PRIVATE, fd, 0);
	if (ptr == MAP_FAILED)
		return 3;

	start_func start = (start_func) ptr;
	printf("start = %p\n", start);

	int32_t result = start();
	printf("result = %d\n", result);

	if (result != MAGIC)
		return 4;

	return 0;
}
