// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"github.com/tsavola/wag/object/debug/dump"
	"github.com/tsavola/wag/static"
	"github.com/tsavola/wag/wa"
)

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

func makeMem(size int, extraFlags int) (mem []byte, err error) {
	if size > 0 {
		mem, err = syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|extraFlags)
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
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] wasmfile\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
		flag.PrintDefaults()
	}

	var (
		textSize  = 128 * 1024 * 1024
		stackSize = 64 * 1024
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

	vecTextMem, err := makeMem(vecSize+textSize, 0)
	if err != nil {
		log.Fatal(err)
	}

	vecMem := vecTextMem[:vecSize]
	copy(vecMem[vecSize-len(importVector):], importVector)

	textMem := vecTextMem[vecSize:]
	textAddr := memAddr(textMem)
	textBuf := static.Buf(textMem)

	config := &wag.Config{
		Text:            textBuf,
		MemoryAlignment: os.Getpagesize(),
		Entry:           entry,
	}
	obj, err := wag.Compile(config, progReader, resolver{})
	if dumpText {
		e := dump.Text(os.Stdout, obj.Text, textAddr, obj, &obj.Names)
		if err == nil {
			err = e
		}
	}
	if err != nil {
		log.Fatal(err)
	}

	memoryAddr := memAddr(obj.GlobalsMemory) + uintptr(obj.MemoryOffset)
	initMemoryEnd := memoryAddr + uintptr(obj.InitialMemorySize)
	growMemoryEnd := memoryAddr + uintptr(obj.MemorySizeLimit)

	if err := syscall.Mprotect(vecMem, syscall.PROT_READ); err != nil {
		log.Fatal(err)
	}

	if err := syscall.Mprotect(textMem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		log.Fatal(err)
	}

	stackMem, err := makeMem(stackSize, syscall.MAP_STACK)
	if err != nil {
		log.Fatal(err)
	}
	stackOffset := stackSize - len(obj.StackFrame)
	copy(stackMem[stackOffset:], obj.StackFrame)

	stackAddr := memAddr(stackMem)
	stackLimit := stackAddr + signalStackReserve
	stackPtr := stackAddr + uintptr(stackOffset)

	if stackLimit >= stackPtr {
		log.Fatal("stack is too small for starting program")
	}

	exec(textAddr, stackLimit, memoryAddr, initMemoryEnd, growMemoryEnd, stackPtr)
}
