GO		:= go
GOPATH		:= $(PWD)

export GOPATH

BUILD_SUITE_DIR	:= src/github.com/WebAssembly/build-suite
SEXPR_WASM_DIR	:= src/github.com/WebAssembly/sexpr-wasm-prototype
SEXPR_WASM	:= $(SEXPR_WASM_DIR)/out/sexpr-wasm

check: testsuite/hello_world.wasm
	$(GO) fmt .
	$(GO) vet .
	$(GO) test -v .

testsuite/%.wasm: $(BUILD_SUITE_DIR)/emscripten/%/src.cpp.o.wast $(SEXPR_WASM)
	mkdir -p $(dir $@)
	$(SEXPR_WASM) -o $@ $(BUILD_SUITE_DIR)/emscripten/$*/src.cpp.o.wast

$(SEXPR_WASM):
	mkdir -p $(dir $(SEXPR_WASM))
	$(MAKE) -C $(SEXPR_WASM_DIR)

.PHONY: check
