// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/internal/test/runner/imports"
	"github.com/tsavola/wag/object/debug"
	"github.com/tsavola/wag/object/stack"
	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

const signalStackReserve = 8192

func run(text []byte, initialMemorySize int, memoryAddr uintptr, stack []byte, stackOffset, resumeResult, slaveFd int, testArg int64) (trapId uint64, currentMemorySize int, stackPtr uintptr)

func importTrapHandler() uint64
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
			VecIndex: -3,
			Addr:     importSpectestPrint(),
			Variadic: true,
		},
	},
	"wag": {
		"get_arg": imports.Func{
			VecIndex: -4,
			Addr:     importGetArg(),
			FuncType: wa.FuncType{
				Result: wa.I64,
			},
		},
		"snapshot": imports.Func{
			VecIndex: -5,
			Addr:     importSnapshot(),
			FuncType: wa.FuncType{
				Result: wa.I32,
			},
		},
	},
	"env": {
		"putns": imports.Func{
			VecIndex: -6,
			Addr:     importPutns(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I32, wa.I32},
			},
		},
		"benchmark_begin": imports.Func{
			VecIndex: -7,
			Addr:     importBenchmarkBegin(),
			FuncType: wa.FuncType{
				Result: wa.I64,
			},
		},
		"benchmark_end": imports.Func{
			VecIndex: -8,
			Addr:     importBenchmarkEnd(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I64},
				Result: wa.I32,
			},
		},
		"benchmark_barrier": imports.Func{
			VecIndex: -9,
			Addr:     importBenchmarkBarrier(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I64, wa.I64},
				Result: wa.I64,
			},
		},
	},
}

func populateImportVector(b []byte) {
	binary.LittleEndian.PutUint64(b[len(b)-16:], importTrapHandler())
	// set grow memory limit later

	for _, m := range importFuncs {
		for _, f := range m {
			binary.LittleEndian.PutUint64(b[len(b)+f.VecIndex*8:], f.Addr)
		}
	}
}

type res struct{}

func (res) ResolveVariadicFunc(module, field string, sig wa.FuncType) (variadic bool, index int, err error) {
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
	index = f.VecIndex
	return
}

func (r res) ResolveFunc(module, field string, sig wa.FuncType) (index int, err error) {
	_, index, err = r.ResolveVariadicFunc(module, field, sig)
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
	getData() ([]byte, int)
	getStack() []byte
	getResume() int
	writeStacktraceTo(w io.Writer, funcs []wa.FuncType, ns *section.NameSection, stack []byte) error
	exportStack(native []byte) (portable []byte, err error)
}

type Program struct {
	vecText []byte
	vec     []byte

	Text     []byte
	DebugMap debug.InsnMap

	entryFunc uint32
	entryArgs []uint64
	entryAddr int32

	data         []byte
	memoryOffset int

	funcAddrs map[int]int
	callSites map[int]callSite
}

func NewProgram(maxTextSize int, entryFunc uint32, entryArgs []uint64) (p *Program, err error) {
	p = &Program{
		entryFunc: entryFunc,
		entryArgs: entryArgs,
	}

	const vecSize = 4096

	p.vecText, err = makeMemory(vecSize+maxTextSize, syscall.PROT_EXEC, 0)
	if err != nil {
		p.Close()
		return
	}

	p.vec = p.vecText[:vecSize]
	p.Text = p.vecText[vecSize:]

	populateImportVector(p.vec)
	return
}

func (p *Program) TextAddr() uintptr {
	return (*reflect.SliceHeader)(unsafe.Pointer(&p.Text)).Data
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

	return
}

func (p *Program) Close() (first error) {
	if p.vecText != nil {
		if err := syscall.Munmap(p.vecText); err != nil && first == nil {
			first = err
		}
	}

	return
}

func (p *Program) getText() []byte {
	return p.Text
}

func (p *Program) getData() (data []byte, memoryOffset int) {
	data = p.data
	memoryOffset = p.memoryOffset
	return
}

func (p *Program) SetEntryAddr(addr int32) {
	p.entryAddr = addr
}

func (p *Program) resolveEntry() {
	if p.entryFunc == 0 || p.entryAddr != 0 {
		return
	}

	p.entryAddr = p.DebugMap.FuncAddrs[p.entryFunc]
}

func (p *Program) GetStackEntry() (addr int32, args []uint64) {
	p.getStack()
	addr = p.entryAddr
	args = p.entryArgs
	return
}

func (p *Program) getStack() []byte {
	if p.entryFunc != 0 && p.entryAddr == 0 {
		p.resolveEntry()
	}

	return stack.EntryFrame(p.entryAddr, p.entryArgs)
}

func (*Program) getResume() int {
	return 0 // no resume
}

type Runner struct {
	prog runnable

	resolveEntry func()

	globalsMemory []byte
	memoryOffset  int
	memorySize    int
	stack         []byte

	lastTrap     trap.ID
	lastStackPtr uintptr

	Snapshots []*Snapshot
}

func (p *Program) NewRunner(initMemorySize, growMemorySize, stackSize int) (r *Runner, err error) {
	binary.LittleEndian.PutUint64(p.vec[len(p.vec)-8:], uint64(growMemorySize))

	err = syscall.Mprotect(p.vec, syscall.PROT_READ)
	if err != nil {
		return
	}

	r, err = newRunner(p, initMemorySize, growMemorySize, stackSize)
	if err != nil {
		return
	}

	r.resolveEntry = p.resolveEntry
	return
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

	r.stack, err = makeMemory(signalStackReserve+stackSize, 0, 0)
	if err != nil {
		r.Close()
		return
	}

	r.resolveEntry = func() {}
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

func (r *Runner) Run(testArg int64, sigs []wa.FuncType, printer io.Writer) (result int32, err error) {
	e := Executor{
		runner:  r,
		testArg: testArg,
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

	testArg int64
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
		r.resolveEntry() // if event handler was not invoked
		fmt.Fprintf(e.printer, "--- execution starting ---\n")
		defer close(e.done)
		e.run()
	}()

	eventHandler = func(e event.Event) {
		fmt.Fprintf(printer, "--- event: %s ---\n", e)
		if e == event.Init {
			r.resolveEntry()
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
	stack := e.runner.stack[signalStackReserve:]
	stackState := e.runner.prog.getStack()
	stackOffset := len(stack) - len(stackState)
	copy(stack[stackOffset:], stackState)

	resumeResult := e.runner.prog.getResume()

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

	trapId, memorySize, stackPtr := run(e.runner.prog.getText(), int(e.runner.memorySize), memoryAddr, stack, stackOffset, resumeResult, fds[1], e.testArg)

	e.runner.memorySize = memorySize
	e.runner.lastTrap = trap.ID(uint32(trapId))
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
