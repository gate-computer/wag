// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/internal/test/runner/imports"
	"github.com/tsavola/wag/object"
	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

func run(text []byte, initialMemorySize int, memoryAddr, growMemorySize, roDataBase uintptr, stack []byte, stackOffset, resumeResult, slaveFd int, arg int64) (trapId uint64, currentMemorySize int, stackPtr uintptr)

func importGetArg() uint64
func importSnapshot() uint64
func importSpectestPrint() uint64
func importPutns() uint64
func importBenchmarkBegin() uint64
func importBenchmarkEnd() uint64
func importBenchmarkBarrier() uint64

var importFuncs = map[string]map[string]imports.Func{
	"spectest": {
		"print": imports.Func{
			Addr:     importSpectestPrint(),
			Variadic: true,
		},
	},
	"wag": {
		"get_arg": imports.Func{
			Addr: importGetArg(),
			FuncType: wa.FuncType{
				Result: wa.I64,
			},
		},
		"snapshot": imports.Func{
			Addr: importSnapshot(),
			FuncType: wa.FuncType{
				Result: wa.I32,
			},
		},
	},
	"env": {
		"putns": imports.Func{
			Addr: importPutns(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I32, wa.I32},
			},
		},
		"benchmark_begin": imports.Func{
			Addr: importBenchmarkBegin(),
			FuncType: wa.FuncType{
				Result: wa.I64,
			},
		},
		"benchmark_end": imports.Func{
			Addr: importBenchmarkEnd(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I64},
				Result: wa.I32,
			},
		},
		"benchmark_barrier": imports.Func{
			Addr: importBenchmarkBarrier(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I64, wa.I64},
				Result: wa.I64,
			},
		},
	},
}

type res struct{}

func (res) ResolveVariadicFunc(module, field string, sig wa.FuncType) (variadic bool, addr uint64, err error) {
	f, found := importFuncs[module][field]
	if !found {
		err = fmt.Errorf("imported function not found: %s %s %s", module, field, sig)
		return
	}

	if !f.Implements(sig) {
		err = fmt.Errorf("imported function %s %s has incompatible signature: %s", module, field, sig)
		return
	}

	variadic = f.Variadic
	addr = f.Addr
	return
}

func (r res) ResolveFunc(module, field string, sig wa.FuncType) (addr uint64, err error) {
	_, addr, err = r.ResolveVariadicFunc(module, field, sig)
	return
}

func (res) ResolveGlobal(module, field string, t wa.Type) (init uint64, err error) {
	switch module {
	case "spectest":
		switch field {
		case "global", "global_i32":
			return
		}
	}

	err = fmt.Errorf("imported %s global not found: %s %s", t, module, field)
	return
}

var Resolver res

type runnable interface {
	getText() []byte
	getRODataAddr() uintptr
	getData() ([]byte, int)
	getStack() []byte
	writeStacktraceTo(w io.Writer, funcs []wa.FuncType, ns *section.NameSection, stack []byte) error
	exportStack(native []byte) (portable []byte, err error)
}

type Program struct {
	Text    []byte
	ROData  []byte
	ObjInfo object.CallMap

	data         []byte
	memoryOffset int

	funcAddrs map[int]int
	callSites map[int]callSite
}

func NewProgram(maxTextSize, maxRODataSize int) (p *Program, err error) {
	p = &Program{}

	p.Text, err = makeMemory(maxTextSize, syscall.PROT_EXEC, 0)
	if err != nil {
		p.Close()
		return
	}

	p.ROData, err = makeMemory(maxRODataSize, 0, roDataFlags)
	if err != nil {
		p.Close()
		return
	}

	return
}

func (p *Program) TextAddr() uintptr {
	return (*reflect.SliceHeader)(unsafe.Pointer(&p.Text)).Data
}

func (p *Program) RODataAddr() uintptr {
	return (*reflect.SliceHeader)(unsafe.Pointer(&p.ROData)).Data
}

func (p *Program) SetData(data []byte, memoryOffset int) {
	p.data = data
	p.memoryOffset = memoryOffset
}

func (p *Program) Seal() (err error) {
	if p.Text != nil {
		err = syscall.Mprotect(p.Text, syscall.PROT_READ|syscall.PROT_EXEC)
		if err != nil {
			return
		}
	}

	if p.ROData != nil {
		err = syscall.Mprotect(p.ROData, syscall.PROT_READ)
		if err != nil {
			return
		}
	}

	return
}

func (p *Program) Close() (first error) {
	if p.Text != nil {
		if err := syscall.Munmap(p.Text); err != nil && first == nil {
			first = err
		}
	}

	if p.ROData != nil {
		if err := syscall.Munmap(p.ROData); err != nil && first == nil {
			first = err
		}
	}

	return
}

func (p *Program) getText() []byte {
	return p.Text
}

func (p *Program) getRODataAddr() uintptr {
	return p.RODataAddr()
}

func (p *Program) getData() (data []byte, memoryOffset int) {
	data = p.data
	memoryOffset = p.memoryOffset
	return
}

func (p *Program) getStack() []byte {
	return nil
}

type Runner struct {
	prog runnable

	globalsMemory []byte
	memoryOffset  int
	memorySize    int
	stack         []byte

	lastTrap     trap.Id
	lastStackPtr uintptr

	Snapshots []*Snapshot
}

func (p *Program) NewRunner(initMemorySize, growMemorySize, stackSize int) (r *Runner, err error) {
	return newRunner(p, initMemorySize, growMemorySize, stackSize)
}

func newRunner(prog runnable, initMemorySize, growMemorySize, stackSize int) (r *Runner, err error) {
	if (initMemorySize & (wa.PageSize - 1)) != 0 {
		err = fmt.Errorf("initial memory size is not multiple of %d", wa.PageSize)
		return
	}
	if (growMemorySize & (wa.PageSize - 1)) != 0 {
		err = fmt.Errorf("memory growth limit is not multiple of %d", wa.PageSize)
		return
	}

	data, memoryOffset := prog.getData()

	if int(initMemorySize) < len(data)-memoryOffset {
		err = errors.New("data does not fit in initial memory")
		return
	}
	if initMemorySize > growMemorySize {
		err = errors.New("initial memory exceeds memory growth limit")
		return
	}

	if initMemorySize > 0x7fffffff {
		err = errors.New("initial memory size must be below 2 GB")
		return
	}
	if growMemorySize > 0x7fffffff {
		err = errors.New("memory growth limit must be below 2 GB")
		return
	}

	r = &Runner{
		prog:         prog,
		memoryOffset: memoryOffset,
		memorySize:   initMemorySize,
	}

	r.globalsMemory, err = makeMemory(memoryOffset+int(growMemorySize), 0, 0)
	if err != nil {
		r.Close()
		return
	}

	copy(r.globalsMemory, data)

	r.stack, err = makeMemory(stackSize, 0, 0)
	if err != nil {
		r.Close()
		return
	}

	return
}

func (r *Runner) Close() (first error) {
	if r.stack != nil {
		if err := syscall.Munmap(r.stack); err != nil && first == nil {
			first = err
		}
	}

	if r.globalsMemory != nil {
		if err := syscall.Munmap(r.globalsMemory); err != nil && first == nil {
			first = err
		}
	}

	return
}

func (r *Runner) Run(arg int64, sigs []wa.FuncType, printer io.Writer) (result int32, err error) {
	e := Executor{
		runner:  r,
		arg:     arg,
		sigs:    sigs,
		printer: printer,
	}
	e.run()
	result = e.result
	err = e.err
	return
}

type Executor struct {
	runner *Runner

	arg     int64
	sigs    []wa.FuncType
	printer io.Writer

	cont chan struct{}
	done chan struct{}

	result int32
	err    error
}

func (r *Runner) NewExecutor(sigs []wa.FuncType, printer io.Writer) (e *Executor, eventHandler func(event.Event)) {
	e = &Executor{
		runner:  r,
		sigs:    sigs,
		printer: printer,
		cont:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	start := make(chan struct{})

	go func() {
		select {
		case <-start:
		case <-e.cont:
		}
		fmt.Fprintf(e.printer, "--- execution starting ---\n")
		defer close(e.done)
		e.run()
	}()

	eventHandler = func(e event.Event) {
		fmt.Fprintf(printer, "--- event: %s ---\n", e)
		if e == event.Init {
			close(start)
		}
	}
	return
}

func (e *Executor) Wait() (result int32, err error) {
	fmt.Fprintf(e.printer, "--- code generation complete ---\n")
	close(e.cont)

	<-e.done
	fmt.Fprintf(e.printer, "--- execution finished ---\n")

	result = e.result
	err = e.err
	return
}

func (e *Executor) run() {
	stackState := e.runner.prog.getStack()
	stackOffset := len(e.runner.stack) - len(stackState)
	copy(e.runner.stack[stackOffset:], stackState)

	resumeResult := 0 // don't resume
	if len(stackState) > 0 {
		resumeResult = -1 // resume; return this value to snapshot function caller
	}

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return
	}

	done := make(chan struct{})

	defer func() {
		syscall.Close(fds[1])
		<-done
	}()

	go func() {
		defer close(done)
		e.slave(fds[0], e.sigs, e.printer, e.cont)
	}()

	globalsMemoryAddr := (*reflect.SliceHeader)(unsafe.Pointer(&e.runner.globalsMemory)).Data
	memoryAddr := globalsMemoryAddr + uintptr(e.runner.memoryOffset)
	growMemorySize := len(e.runner.globalsMemory) - e.runner.memoryOffset

	trapId, memorySize, stackPtr := run(e.runner.prog.getText(), int(e.runner.memorySize), memoryAddr, uintptr(growMemorySize), e.runner.prog.getRODataAddr(), e.runner.stack, stackOffset, resumeResult, fds[1], e.arg)

	e.runner.memorySize = memorySize
	e.runner.lastTrap = trap.Id(uint32(trapId))
	e.runner.lastStackPtr = stackPtr

	if e.runner.lastTrap == trap.Exit {
		e.result = int32(uint32(trapId >> 32))
	} else {
		e.err = e.runner.lastTrap
	}
	return
}

func makeMemory(size int, extraProt, extraFlags int) (mem []byte, err error) {
	if size == 0 {
		return
	}

	return syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE|extraProt, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|extraFlags)
}
