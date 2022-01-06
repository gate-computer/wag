// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Program wasys implements a standalone toy compiler and runtime.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"gate.computer/wag"
	"gate.computer/wag/buffer"
	"gate.computer/wag/compile"
	"gate.computer/wag/object/debug/dump"
	"gate.computer/wag/wa"
)

const linearMemoryAddressSpace = 8 * 1024 * 1024 * 1024

var (
	verbose = false
)

var (
	importFuncs  = make(map[string]int)
	importVector []byte
)

type sysResolver struct{}

func (sysResolver) ResolveFunc(module, field string, sig wa.FuncType) (index int, err error) {
	index = importFuncs[field]
	return
}

type libResolver struct {
	lib compile.Library
}

func (r libResolver) ResolveFunc(module, field string, sig wa.FuncType) (index uint32, err error) {
	if verbose {
		log.Printf("import %s%s", field, sig)
	}

	if module != "env" {
		err = fmt.Errorf("import function's module is unknown: %s %s", module, field)
		return
	}

	name := field + "_"
	for _, t := range sig.Params {
		name += t.String()
	}
	if len(sig.Results) > 0 {
		name += "_"
		for _, t := range sig.Results {
			name += t.String()
		}
	}

	index, sig, found := r.lib.ExportFunc(name)
	if !found {
		err = fmt.Errorf("import function not supported: %s%s", field, sig)
		return
	}

	return
}

func (libResolver) ResolveGlobal(module, field string, t wa.Type) (init uint64, err error) {
	err = fmt.Errorf("imported global not supported: %s %s", module, field)
	return
}

func makeMem(size int, prot, extraFlags int) (mem []byte, err error) {
	if size > 0 {
		mem, err = syscall.Mmap(-1, 0, size, prot, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|extraFlags)
	}
	return
}

func alignSize(size, alignment int) int {
	return (size + (alignment - 1)) &^ (alignment - 1)
}

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] wasmfile\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	var (
		textSize  = compile.MaxTextSize
		stackSize = wa.PageSize
		entry     = "main"
		dumpText  = false
	)

	flag.BoolVar(&verbose, "v", verbose, "verbose logging")
	flag.IntVar(&textSize, "textsize", textSize, "maximum program text size")
	flag.IntVar(&stackSize, "stacksize", stackSize, "call stack size")
	flag.StringVar(&entry, "entry", entry, "function to run")
	flag.BoolVar(&dumpText, "dumptext", dumpText, "disassemble the generated code to stdout")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	filename := flag.Arg(0)

	prog, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	progReader := bytes.NewReader(prog)

	vecSize := alignSize(len(importVector), os.Getpagesize())

	vecTextMem, err := makeMem(vecSize+textSize, syscall.PROT_READ|syscall.PROT_WRITE, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.KeepAlive(vecTextMem)

	vecMem := vecTextMem[:vecSize]
	vec := vecMem[vecSize-len(importVector):]
	copy(vec, importVector)

	textMem := vecTextMem[vecSize:]
	textAddr := uintptr(unsafe.Pointer(&textMem[0]))
	textBuf := buffer.NewStatic(textMem[:0:len(textMem)])

	lib, err := wag.CompileLibrary(bytes.NewReader(libWASM), sysResolver{})
	if err != nil {
		panic(err)
	}

	config := &wag.Config{
		ImportResolver:  libResolver{lib},
		Text:            textBuf,
		MemoryAlignment: os.Getpagesize(),
		Entry:           entry,
	}
	obj, err := wag.Compile(config, progReader, lib)
	if dumpText && len(obj.Text) > 0 {
		e := dump.Text(os.Stdout, obj.Text, textAddr, obj.FuncAddrs, &obj.Names)
		if err == nil {
			err = e
		}
	}
	if err != nil {
		log.Fatal(err)
	}

	globalsMemory, err := makeMem(obj.MemoryOffset+linearMemoryAddressSpace, syscall.PROT_NONE, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.KeepAlive(globalsMemory)

	err = syscall.Mprotect(globalsMemory[:obj.MemoryOffset+obj.InitialMemorySize], syscall.PROT_READ|syscall.PROT_WRITE)
	if err != nil {
		log.Fatal(err)
	}

	copy(globalsMemory, obj.GlobalsMemory)

	setImportVectorMemoryAddr(vec, uintptr(unsafe.Pointer(&globalsMemory[obj.MemoryOffset])))

	if err := syscall.Mprotect(vecMem, syscall.PROT_READ); err != nil {
		log.Fatal(err)
	}

	if err := syscall.Mprotect(textMem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		log.Fatal(err)
	}

	stackMem, err := makeMem(stackSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_STACK)
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.KeepAlive(stackMem)

	stackOffset := stackSize - len(obj.StackFrame)
	copy(stackMem[stackOffset:], obj.StackFrame)

	stackLimit := uintptr(unsafe.Pointer(&stackMem[256+8192+240+8+8]))
	stackPtr := uintptr(unsafe.Pointer(&stackMem[stackOffset]))

	if stackLimit >= stackPtr {
		log.Fatal("stack is too small to start program")
	}

	exec(textAddr, stackLimit, stackPtr)
}
