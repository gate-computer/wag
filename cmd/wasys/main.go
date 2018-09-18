// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

//go:generate go run internal/cmd/syscalls/generate.go

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
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/object/debug/dump"
	"github.com/tsavola/wag/static"
)

var (
	verbose = false
)

type importFunc struct {
	absAddr uint64
	params  int
}

var importFuncs = make(map[string]importFunc)

type env struct{}

func (*env) ImportFunc(module, field string, sig abi.Sig) (variadic bool, absAddr uint64, err error) {
	if verbose {
		log.Printf("import %s%s", field, sig)
	}

	if module != "env" {
		err = fmt.Errorf("import function's module is unknown: %s %s", module, field)
		return
	}

	i := importFuncs[field]
	if i.absAddr == 0 {
		err = fmt.Errorf("import function not supported: %s", field)
		return
	}
	if len(sig.Args) != i.params {
		err = fmt.Errorf("%s: import function has wrong number of parameters: import signature has %d, syscall wrapper has %d", field, len(sig.Args), i.params)
		return
	}

	absAddr = i.absAddr
	return
}

func (*env) ImportGlobal(module, field string, t abi.Type) (valueBits uint64, err error) {
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

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] wasmfile\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
		flag.PrintDefaults()
	}

	var (
		textSize    = 128 * 1024 * 1024
		roDataSize  = 4 * 1024 * 1024
		stackSize   = 64 * 1024
		entrySymbol = "main"
		dumpText    = false
		dumpROData  = false
	)

	flag.BoolVar(&verbose, "v", verbose, "verbose logging")
	flag.IntVar(&textSize, "textsize", textSize, "maximum program text size")
	flag.IntVar(&roDataSize, "rodatasize", roDataSize, "maximum read-only data size")
	flag.IntVar(&stackSize, "stacksize", stackSize, "call stack size")
	flag.StringVar(&entrySymbol, "func", entrySymbol, "function to run")
	flag.BoolVar(&dumpText, "dumptext", dumpText, "disassemble the generated code to stdout")
	flag.BoolVar(&dumpROData, "dumprodata", dumpROData, "dump the generated read-only data to stdout")
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

	roDataMem, err := makeMem(roDataSize, roDataFlags)
	if err != nil {
		log.Fatal(err)
	}
	roDataAddr := memAddr(roDataMem)
	roDataBuf := static.Buf(roDataMem)

	textMem, err := makeMem(textSize, 0)
	if err != nil {
		log.Fatal(err)
	}
	textAddr := memAddr(textMem)
	textBuf := static.Buf(textMem)

	config := &wag.Config{
		EntrySymbol:     entrySymbol,
		EntryArgs:       make([]uint64, 2),
		Text:            textBuf,
		ROData:          roDataBuf,
		RODataAddr:      roDataAddr,
		MemoryAlignment: os.Getpagesize(),
	}
	obj, err := wag.Compile(config, progReader, &env{})
	if dumpText {
		e := dump.Text(os.Stdout, obj.Text, textAddr, roDataAddr, obj.FuncAddrs, &obj.Names)
		if err == nil {
			err = e
		}
	}
	if dumpROData {
		e := dump.ROData(os.Stdout, obj.ROData, 0)
		if err == nil {
			err = e
		}
	}
	if err != nil {
		log.Fatal(err)
	}

	memoryAddr := memAddr(obj.GlobalsMemory) + uintptr(obj.MemoryOffset)
	initMemoryEnd := memoryAddr + uintptr(obj.InitMemorySize)
	growMemoryEnd := memoryAddr + uintptr(obj.GrowMemoryLimit)

	if err := syscall.Mprotect(roDataMem, syscall.PROT_READ); err != nil {
		log.Fatal(err)
	}

	if err := syscall.Mprotect(textMem, syscall.PROT_EXEC); err != nil {
		log.Fatal(err)
	}

	stackMem, err := makeMem(stackSize, syscall.MAP_STACK)
	if err != nil {
		log.Fatal(err)
	}
	stackAddr := memAddr(stackMem)
	stackEnd := stackAddr + uintptr(stackSize)

	stackLimit := stackAddr + 512 + 128 // some space for register context and red zone

	exec(textAddr, stackLimit, memoryAddr, initMemoryEnd, growMemoryEnd, stackEnd, roDataAddr)
}
