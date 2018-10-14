// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wag provides a high-level WebAssembly compiler API.
//
// See the Compile function's source code for an example of how to use the
// low-level compiler APIs (implemented in subpackages).
package wag

import (
	"github.com/tsavola/wag/binding"
	"github.com/tsavola/wag/compile"
	"github.com/tsavola/wag/object/debug"
	"github.com/tsavola/wag/object/stack"
	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/wa"
)

// EntryPolicy validates an entry function's signature while looking it up from
// a module's exported functions.
type EntryPolicy func(m *compile.Module, symbol string) (globalIndex uint32, sig wa.FuncType, err error)

// Config for a single compiler invocation.  Zero values are replaced with
// effective defaults during compilation.
type Config struct {
	Text            compile.CodeBuffer // Defaults to dynamically sized buffer.
	GlobalsMemory   compile.DataBuffer // Defaults to dynamically sized buffer.
	MemoryAlignment int                // Defaults to minimal valid alignment.
	Entry           string             // No entry function by default.
	EntryPolicy     EntryPolicy        // Defaults to binding.GetMainFunc.
	EntryArgs       []uint64           // Defaults to zeros (subject to policy).
}

// Object code with debug information.  The fields are roughly in order of
// appearance during compilation.
//
// Executing the code requires a platform-specific mechanism; it's not
// supported by this package.
type Object struct {
	FuncTypes         []wa.FuncType       // Signatures for debug output.
	InitialMemorySize int                 // Current memory allocation.
	MemorySizeLimit   int                 // Maximum valid value if not limited.
	Text              []byte              // Machine code and read-only data.
	debug.InsnMap                         // Stack unwinding and debug metadata.
	MemoryOffset      int                 // Threshold between globals and memory.
	GlobalsMemory     []byte              // Global values and memory contents.
	StackFrame        []byte              // Entry function address and arguments.
	Names             section.NameSection // Symbols for debug output.
}

// Compile a WebAssembly binary module into machine code.  The Object is
// constructed incrementally so that populated fields may be inspected on
// error.
//
// See the source code for examples of how to use the lower-level APIs.
func Compile(objectConfig *Config, r compile.Reader, imports binding.ImportResolver) (object *Object, err error) {
	object = new(Object)

	// In general, custom sections may appear at any position in the binary
	// module, so the custom section loader must be available at every step.
	// (WebAssembly specification says that the name section can appear only
	// after the data section, but wag's custom section handling is decoupled
	// from standard section handling; just accept it at any point.)

	var customSections = section.CustomLoaders{
		section.CustomName: object.Names.Load,
	}

	var loadingConfig = compile.Config{
		CustomSectionLoader: customSections.Load,
	}

	// Parse the module specification while reading the WebAssembly sections
	// preceding the actual program code.  (The Module object needs to be
	// available during compilation and when looking up entry functions, but
	// the program can be executed without it.)

	var moduleConfig = &compile.ModuleConfig{
		Config: loadingConfig,
	}

	module, err := compile.LoadInitialSections(moduleConfig, r)
	if err != nil {
		return
	}

	object.FuncTypes = module.FuncTypes()
	object.InitialMemorySize = module.InitialMemorySize()
	object.MemorySizeLimit = module.MemorySizeLimit()

	// Fill in host function addresses and global variables' values.

	err = binding.BindImports(module, imports)
	if err != nil {
		return
	}

	// Generate executable code and debug information while reading the
	// WebAssembly code section.  Text encodes the import function vector
	// indexes, but not the function addresses (the vector can be mapped
	// separately during execution).  It is also independent of entry function
	// choice and program state.

	var codeConfig = &compile.CodeConfig{
		Text:   objectConfig.Text,
		Mapper: &object.CallMap,
		Config: loadingConfig,
	}

	err = compile.LoadCodeSection(codeConfig, r, module)
	if err != nil {
		return
	}

	objectConfig.Text = codeConfig.Text
	object.Text = codeConfig.Text.Bytes()

	// Generate initial linear memory contents while reading the WebAssembly
	// data section.  This step also copies the global variables' initial
	// values into the same buffer, just before the memory contents.
	// MemoryAlignment causes padding to be inserted before the globals.

	var dataConfig = &compile.DataConfig{
		GlobalsMemory:   objectConfig.GlobalsMemory,
		MemoryAlignment: objectConfig.MemoryAlignment,
		Config:          loadingConfig,
	}

	err = compile.LoadDataSection(dataConfig, r, module)
	if err != nil {
		return
	}

	objectConfig.GlobalsMemory = dataConfig.GlobalsMemory
	objectConfig.MemoryAlignment = dataConfig.MemoryAlignment
	object.MemoryOffset = alignSize(module.GlobalsSize(), dataConfig.MemoryAlignment)
	object.GlobalsMemory = dataConfig.GlobalsMemory.Bytes()

	// Find the export function which will be used as the optional entry point.
	// (It is executed after the start function which is defined by the module
	// specification.)  CallMap is used to look up the address.

	var (
		entryIndex uint32
		entryType  wa.FuncType
		entryAddr  int32
	)

	if objectConfig.Entry != "" {
		if objectConfig.EntryPolicy == nil {
			objectConfig.EntryPolicy = binding.GetMainFunc
		}

		entryIndex, entryType, err = objectConfig.EntryPolicy(module, objectConfig.Entry)
		if err != nil {
			return
		}

		entryAddr = object.FuncAddrs[entryIndex]
	}

	// Form a stack frame for the init routine which calls the entry function.
	// Add zeros if all arguments weren't provided but the policy was lenient.

	var entryArgs []uint64

	if n := len(entryType.Params); len(objectConfig.EntryArgs) >= n {
		entryArgs = objectConfig.EntryArgs[:n]
	} else {
		entryArgs = make([]uint64, n)
		copy(entryArgs, objectConfig.EntryArgs)
	}

	object.StackFrame = stack.EntryFrame(entryAddr, entryArgs)

	// Read the whole binary module to get the name section.

	err = compile.LoadCustomSections(&loadingConfig, r)
	if err != nil {
		return
	}

	return
}

// alignSize rounds up.
func alignSize(size, alignment int) int {
	return (size + (alignment - 1)) &^ (alignment - 1)
}
