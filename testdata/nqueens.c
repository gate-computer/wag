// clang --target=wasm32 -Oz -fomit-frame-pointer -nostdlib -Wl,--allow-undefined -Wl,--no-entry -Wl,--export=benchmark_main -o nqueens.wasm nqueens.c

#include <stdint.h>

uint64_t benchmark_begin(void);
int benchmark_end(uint64_t);
int64_t benchmark_barrier(int64_t value, uint64_t dummy);

#define MAXN 31

// copied from https://rosettacode.org/wiki/N-queens_problem#C
// licensed under GNU Free Documentation License 1.2
__attribute__ ((noinline))
int nqueens(int n)
{
	int q0,q1;
	int cols[MAXN], diagl[MAXN], diagr[MAXN], posibs[MAXN]; // Our backtracking 'stack'
	int num=0;
	//
	// The top level is two fors, to save one bit of symmetry in the enumeration by forcing second queen to
	// be AFTER the first queen.
	//
	for (q0=0; q0<n-2; q0++) {
		for (q1=q0+2; q1<n; q1++){
			int bit0 = 1<<q0;
			int bit1 = 1<<q1;
			int d=0; // d is our depth in the backtrack stack
			cols[0] = bit0 | bit1 | (-1<<n); // The -1 here is used to fill all 'coloumn' bits after n ...
			diagl[0]= (bit0<<1 | bit1)<<1;
			diagr[0]= (bit0>>1 | bit1)>>1;

			//  The variable posib contains the bitmask of possibilities we still have to try in a given row ...
			int posib = ~(cols[0] | diagl[0] | diagr[0]);

			while (d >= 0) {
				while(posib) {
					int bit = posib & -posib; // The standard trick for getting the rightmost bit in the mask
					int ncols= cols[d] | bit;
					int ndiagl = (diagl[d] | bit) << 1;
					int ndiagr = (diagr[d] | bit) >> 1;
					int nposib = ~(ncols | ndiagl | ndiagr);
					posib^=bit; // Eliminate the tried possibility.

					// The following is the main additional trick here, as recognizing solution can not be done using stack level (d),
					// since we save the depth+backtrack time at the end of the enumeration loop. However by noticing all coloumns are
					// filled (comparison to -1) we know a solution was reached ...
					// Notice also that avoiding an if on the ncols==-1 comparison is more efficient!
					num += ncols==-1;

					if (nposib) {
						if (posib) { // This if saves stack depth + backtrack operations when we passed the last possibility in a row.
							posibs[d++] = posib; // Go lower in stack ..
						}
						cols[d] = ncols;
						diagl[d] = ndiagl;
						diagr[d] = ndiagr;
						posib = nposib;
					}
				}
				posib = posibs[--d]; // backtrack ...
			}
		}
	}
	return num*2;
}

int benchmark_main(void)
{
	uint64_t state = benchmark_begin();

	int count = 8;

	for (int i = 0; i < 10000; i++)
		count = benchmark_barrier(count, nqueens(count));

	return benchmark_end(state);
}

#ifdef STANDALONE
#include <stdio.h>

uint64_t benchmark_begin(void)
{
	uint64_t begin;

	asm volatile(
		"  cpuid                 \n" // serialize
		"  rdtsc                 \n"
		"  shl     $32, %%rdx    \n"
		"  or      %%rdx, %%rax  \n"
		: "=a"(begin)
		:
		: "cc", "rcx", "rdx");

	return begin;
}

int benchmark_end(uint64_t begin)
{
	uint64_t end;

	asm volatile(
		"  rdtsc                 \n"
		"  shl     $32, %%rdx    \n"
		"  or      %%rdx, %%rax  \n"
		: "=a"(end)
		:
		: "cc", "rdx");

	int64_t diff = end - begin;
	if (diff >= 0x80000000)
		diff = -1;

	return diff;
}

int64_t benchmark_barrier(int64_t value, uint64_t dummy)
{
	int64_t ret;

	asm volatile(
		""
		: "=a"(ret)
		: "a"(value), "D"(dummy)
		: "memory");

	return ret;
}

int main(void)
{
	int result = benchmark_main();
	if (result < 0) {
		printf("TSC measurement out of range\n");
		return 1;
	} else {
		printf("%d measures\n", result);
		return 0;
	}
}
#endif
