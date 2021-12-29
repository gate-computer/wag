#!/bin/sh -e

library=$(dirname "$0")
testdata="${library}/.."

set -x

exec ${WASM_CC:-${CC:-clang}} \
	--target=wasm32 \
	-std=c11 \
	-Os \
	-finline-functions \
	-fomit-frame-pointer \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-nostdlib \
	-I"${testdata}/include" \
	$@ \
	"${library}/library.c"
