#!/bin/sh -e

library=$(dirname "$0")
testdata="${library}/.."

exec ${WASM_CC:-${CC:-clang}} \
	--target=wasm32-unknown-unknown \
	-Os -finline-functions -fomit-frame-pointer \
	-Wall -Wextra -Wno-unused-parameter \
	-nostdlib \
	-Wl,--allow-undefined \
	-Wl,--export=spectest_print \
	-Wl,--export=spectest_print_f32 \
	-Wl,--export=spectest_print_f64 \
	-Wl,--export=spectest_print_f64_f64 \
	-Wl,--export=spectest_print_i32 \
	-Wl,--export=spectest_print_i32_f32 \
	-Wl,--export=test_func \
	-Wl,--export=test_func_f32 \
	-Wl,--export=test_func_i32 \
	-Wl,--export=test_func_i32_to_i32 \
	-Wl,--export=test_func_i64_to_i64 \
	-Wl,--export=test_func_to_f32 \
	-Wl,--export=test_func_to_i32 \
	-Wl,--no-entry \
	-I"${testdata}/include" \
	"$@" \
	"${library}/library.c"
