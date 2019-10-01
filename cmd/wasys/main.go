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
	"reflect"
	"syscall"
	"unsafe"

	"github.com/tsavola/wag"
	"github.com/tsavola/wag/buffer"
	"github.com/tsavola/wag/compile"
	"github.com/tsavola/wag/object/debug/dump"
	"github.com/tsavola/wag/wa"
)

const linearMemoryAddressSpace = 8 * 1024 * 1024 * 1024
const signalStackReserve = 8192

var (
	verbose = false
)

type importFunc struct {
	index  int
	params int
}

var (
	importFuncs  = make(map[string]importFunc)
	importVector []byte
)

type resolver struct{}

func (resolver) ResolveFunc(module, field string, sig wa.FuncType) (index int, err error) {
	if verbose {
		log.Printf("import %s%s", field, sig)
	}

	if module != "env" {
		err = fmt.Errorf("import function's module is unknown: %s %s", module, field)
		return
	}

	i := importFuncs[field]
	if i.index == 0 {
		err = fmt.Errorf("import function not supported: %s", field)
		return
	}
	if len(sig.Params) != i.params {
		err = fmt.Errorf("%s: import function has wrong number of parameters: import signature has %d, syscall wrapper has %d", field, len(sig.Params), i.params)
		return
	}

	index = i.index
	return
}

func (resolver) ResolveGlobal(module, field string, t wa.Type) (init uint64, err error) {
	err = fmt.Errorf("imported global not supported: %s %s", module, field)
	return
}

func makeMem(size int, prot, extraFlags int) (mem []byte, err error) {
	if size > 0 {
		mem, err = syscall.Mmap(-1, 0, size, prot, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|extraFlags)
	}
	return
}

func memAddr(mem []byte) uintptr {
	return (*reflect.SliceHeader)(unsafe.Pointer(&mem)).Data
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
		textSize  = compile.DefaultMaxTextSize
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

	vecMem := vecTextMem[:vecSize]
	copy(vecMem[vecSize-len(importVector):], importVector)

	textMem := vecTextMem[vecSize:]
	textAddr := memAddr(textMem)
	textBuf := buffer.NewStatic(textMem[:0:len(textMem)])

	config := &wag.Config{
		Text:            textBuf,
		MemoryAlignment: os.Getpagesize(),
		Entry:           entry,
	}
	obj, err := wag.Compile(config, progReader, resolver{})
	if dumpText && len(obj.Text) > 0 {
		e := dump.Text(os.Stdout, obj.Text, textAddr, obj.FuncAddrs, &obj.Names)
		if err == nil {
			err = e
		}
	}
	if err != nil {
		log.Fatal(err)
	}

	setImportVectorCurrentMemory(obj.InitialMemorySize)

	globalsMemory, err := makeMem(obj.MemoryOffset+linearMemoryAddressSpace, syscall.PROT_NONE, 0)
	if err != nil {
		log.Fatal(err)
	}

	err = syscall.Mprotect(globalsMemory[:obj.MemoryOffset+obj.InitialMemorySize], syscall.PROT_READ|syscall.PROT_WRITE)
	if err != nil {
		log.Fatal(err)
	}

	copy(globalsMemory, obj.GlobalsMemory)

	memoryAddr := memAddr(globalsMemory) + uintptr(obj.MemoryOffset)

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
	stackOffset := stackSize - len(obj.StackFrame)
	copy(stackMem[stackOffset:], obj.StackFrame)

	stackAddr := memAddr(stackMem)
	stackLimit := stackAddr + 16 + signalStackReserve + 128 + 16
	stackPtr := stackAddr + uintptr(stackOffset)

	if stackLimit >= stackPtr {
		log.Fatal("stack is too small for starting program")
	}

	exec(textAddr, stackLimit, memoryAddr, stackPtr)
}
