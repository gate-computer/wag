// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Update ../library.wasm by running 'go generate' in parent directory.

#include <stddef.h>
#include <stdint.h>

#include <rt.h>

enum op {
	NOP,
	PRINT_I32,
	PRINT_I64,
	PRINT_F32,
	PRINT_F64,
};

static inline uint32_t float_bits(float v)
{
	return *(uint32_t *) &v;
}

static inline uint64_t double_bits(double v)
{
	return *(uint64_t *) &v;
}

static inline void write8(uint64_t v)
{
	rt_write8(v);
}

static inline void write44(uint32_t v1, uint32_t v2)
{
	rt_write8(((uint64_t) v1) | (((uint64_t) v2) << 32));
}

static inline void write_header(enum op op1, enum op op2, size_t content_length)
{
	uint64_t size = 8 + 8 + (uint64_t) content_length;
	if (size > 65536)
		rt_trap(TRAP_FAILURE);

	rt_write8(size); // Code, domain and index are zero.
	rt_write8(((uint64_t) op1) | (((uint64_t) op2) << 8));
}

static inline void read_reply(void)
{
	uint64_t header = rt_read8();
	uint32_t size = (uint32_t) header;
	uint32_t misc = (uint32_t) (header >> 32);
	if (misc != 0 || size != 8)
		rt_trap(TRAP_FAILURE);
}

void spectest_print(void) {}

void spectest_print_f32(float v)
{
	write_header(PRINT_F32, NOP, 4);
	write44(float_bits(v), 0);
	read_reply();
}

void spectest_print_f64(double v)
{
	write_header(PRINT_F64, NOP, 8);
	write8(double_bits(v));
	read_reply();
}

void spectest_print_f64_f64(double v1, double v2)
{
	write_header(PRINT_F64, PRINT_F64, 16);
	write8(double_bits(v1));
	write8(double_bits(v2));
	read_reply();
}

void spectest_print_i32(uint32_t v)
{
	write_header(PRINT_I32, NOP, 4);
	write44(v, 0);
	read_reply();
}

void spectest_print_i32_f32(uint32_t v1, float v2)
{
	write_header(PRINT_I32, PRINT_F32, 8);
	write44(v1, float_bits(v2));
	read_reply();
}

void test_func(void) {}
void test_func_f32(float v) {}
void test_func_i32(uint32_t v) {}
uint32_t test_func_i32_to_i32(uint32_t v) { return v; }
uint64_t test_func_i64_to_i64(uint64_t v) { return v; }
float test_func_to_f32(void) { return 0; }
uint32_t test_func_to_i32(void) { return 0; }
