// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/internal/test/runner/imports"
	"github.com/tsavola/wag/object/abi"
	"github.com/tsavola/wag/object/debug"
	"github.com/tsavola/wag/object/stack"
	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

const linearMemoryAddressSpace = 6 * 1024 * 1024 * 1024

const (
	vectorIndexLastImportFunc  = -6
	vectorIndexGrowMemoryLimit = -5
	vectorIndexMemoryAddr      = -4
	vectorIndexCurrentMemory   = -3
	vectorIndexGrowMemory      = -2
	vectorIndexTrapHandler     = -1
)

func run(text []byte, _ uintptr, stack []byte, stackOffset, initOffset, slaveFd int, arg int64, resultFd int, forkStack []byte) int

func importTrapHandler() uint64
func importCurrentMemory() uint64
func importGrowMemory() uint64
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
			VecIndex: vectorIndexLastImportFunc - 0,
			Addr:     importSpectestPrint(),
			Variadic: true,
		},
	},
	"wag": {
		"get_arg": imports.Func{
			VecIndex: vectorIndexLastImportFunc - 1,
			Addr:     importGetArg(),
			FuncType: wa.FuncType{
				Result: wa.I64,
			},
		},
		"snapshot": imports.Func{
			VecIndex: vectorIndexLastImportFunc - 2,
			Addr:     importSnapshot(),
			FuncType: wa.FuncType{
				Result: wa.I32,
			},
		},
		"putns": imports.Func{
			VecIndex: vectorIndexLastImportFunc - 3,
			Addr:     importPutns(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I32, wa.I32},
			},
		},
		"benchmark_begin": imports.Func{
			VecIndex: vectorIndexLastImportFunc - 4,
			Addr:     importBenchmarkBegin(),
			FuncType: wa.FuncType{
				Result: wa.I64,
			},
		},
		"benchmark_end": imports.Func{
			VecIndex: vectorIndexLastImportFunc - 5,
			Addr:     importBenchmarkEnd(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I64},
				Result: wa.I32,
			},
		},
		"benchmark_barrier": imports.Func{
			VecIndex: vectorIndexLastImportFunc - 6,
			Addr:     importBenchmarkBarrier(),
			FuncType: wa.FuncType{
				Params: []wa.Type{wa.I64, wa.I64},
				Result: wa.I64,
			},
		},
	},
}

func populateImportVector(b []byte) {
	// vectorIndexGrowMemoryLimit and vectorIndexMemoryAddr are initialized later.
	binary.LittleEndian.PutUint64(b[len(b)+vectorIndexCurrentMemory*8:], importCurrentMemory())
	binary.LittleEndian.PutUint64(b[len(b)+vectorIndexGrowMemory*8:], importGrowMemory())
	binary.LittleEndian.PutUint64(b[len(b)+vectorIndexTrapHandler*8:], importTrapHandler())

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

	startFunc uint32
	startAddr uint32
	entryFunc uint32
	entryAddr uint32

	data         []byte
	memoryOffset int

	callSites map[int]callSite
}

func NewProgram(maxTextSize int, startFunc, entryFunc uint32) (p *Program, err error) {
	p = &Program{
		startFunc: startFunc,
		entryFunc: entryFunc,
	}

	const vecSize = 4096

	p.vecText, err = makeMemory(vecSize+maxTextSize, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)
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

func (p *Program) SetEntryAddr(addr uint32) {
	p.entryAddr = addr
}

func (p *Program) resolveEntry() {
	if p.startFunc != math.MaxUint32 && p.startAddr == 0 {
		p.startAddr = p.DebugMap.FuncAddrs[p.startFunc]
	}
	if p.entryFunc != math.MaxUint32 && p.entryAddr == 0 {
		p.entryAddr = p.DebugMap.FuncAddrs[p.entryFunc]
	}
}

func (p *Program) getStack() []byte {
	p.resolveEntry()
	return stack.InitFrame(p.startAddr, p.entryAddr)
}

func (*Program) getResume() int {
	return abi.TextAddrEnter
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
	if growMemorySize < 0 {
		growMemorySize = int(math.MaxInt32/wa.PageSize) * wa.PageSize
	}
	binary.LittleEndian.PutUint64(p.vec[len(p.vec)+vectorIndexGrowMemoryLimit*8:], uint64(growMemorySize)/wa.PageSize)

	r, err = newRunner(p, p, initMemorySize, growMemorySize, stackSize)
	if err != nil {
		return
	}

	r.resolveEntry = p.resolveEntry
	return
}

func newRunner(progSnap runnable, realProg *Program, initMemorySize, growMemorySize, stackSize int) (r *Runner, err error) {
	if (initMemorySize & (wa.PageSize - 1)) != 0 {
		err = fmt.Errorf("initial memory size is not multiple of %d", wa.PageSize)
		return
	}
	if (growMemorySize & (wa.PageSize - 1)) != 0 {
		err = fmt.Errorf("memory growth limit is not multiple of %d", wa.PageSize)
		return
	}

	data, memoryOffset := progSnap.getData()

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
		prog:         progSnap,
		memoryOffset: memoryOffset,
		memorySize:   initMemorySize,
	}

	space, err := makeMemory(memoryOffset+linearMemoryAddressSpace, syscall.PROT_NONE)
	if err != nil {
		r.Close()
		return
	}

	r.globalsMemory = space[:memoryOffset+int(growMemorySize)]

	if allocated := r.globalsMemory[:memoryOffset+initMemorySize]; len(allocated) > 0 {
		err = syscall.Mprotect(allocated, syscall.PROT_READ|syscall.PROT_WRITE)
		if err != nil {
			r.Close()
			return
		}
	}

	copy(r.globalsMemory, data)

	memory := r.globalsMemory[memoryOffset:]
	memoryAddr := uint64((*reflect.SliceHeader)(unsafe.Pointer(&memory)).Data)
	binary.LittleEndian.PutUint64(realProg.vec[len(realProg.vec)+vectorIndexMemoryAddr*8:], memoryAddr)

	r.stack, err = makeMemory(stackSize, syscall.PROT_READ|syscall.PROT_WRITE)
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
	stack := e.runner.stack
	binary.LittleEndian.PutUint32(stack, uint32(e.runner.memorySize)/wa.PageSize)
	stackState := e.runner.prog.getStack()
	stackOffset := len(stack) - len(stackState)
	copy(stack[stackOffset:], stackState)

	initOffset := e.runner.prog.getResume()

	slaveSockets, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		panic(err)
	}

	var resultPipe [2]int
	if err := syscall.Pipe2(resultPipe[:], syscall.O_CLOEXEC); err != nil {
		panic(err)
	}

	resultOutput := os.NewFile(uintptr(resultPipe[0]), "|0")
	defer resultOutput.Close()

	slaveDone := make(chan struct{})

	defer func() {
		syscall.Close(slaveSockets[1])
		<-slaveDone
	}()

	go func() {
		defer close(slaveDone)
		e.slave(slaveSockets[0], e.sigs, e.printer, e.cont)
	}()

	globalsMemoryAddr := (*reflect.SliceHeader)(unsafe.Pointer(&e.runner.globalsMemory)).Data
	memoryAddr := globalsMemoryAddr + uintptr(e.runner.memoryOffset)

	text := e.runner.prog.getText()

	forkStack := make([]byte, 65536)

	runResult := run(text, memoryAddr, stack, stackOffset, initOffset, slaveSockets[1], e.testArg, resultPipe[1], forkStack)

	runtime.KeepAlive(forkStack)

	if err := syscall.Close(resultPipe[1]); err != nil {
		panic(err)
	}

	if runResult < 0 {
		panic(fmt.Errorf("run failed with result: %d", runResult))
	}

	switch s := syscall.WaitStatus(runResult); {
	case s.Exited():
		if s.ExitStatus() != 0 {
			panic(fmt.Errorf("run failed with code: %d", s.ExitStatus()))
		}

	case s.Signaled():
		panic(fmt.Errorf("run failed with signal: %s", s.Signal()))

	default:
		panic(fmt.Errorf("run failed with status: %v", s))
	}

	var result struct {
		TrapID     uint64
		MemorySize uint64
		StackPtr   uint64
	}
	if err := binary.Read(resultOutput, byteOrder, &result); err != nil {
		panic(err)
	}

	e.runner.memorySize = int(result.MemorySize)
	e.runner.lastTrap = trap.ID(uint32(result.TrapID))
	e.runner.lastStackPtr = uintptr(result.StackPtr)

	if e.runner.lastTrap == trap.Exit {
		e.result = int32(uint32(result.TrapID >> 32))
	} else {
		e.err = e.runner.lastTrap
	}

	if allocated := e.runner.globalsMemory[e.runner.memoryOffset : e.runner.memoryOffset+e.runner.memorySize]; len(allocated) > 0 {
		if err := syscall.Mprotect(allocated, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
			panic(err)
		}
	}
}

func makeMemory(size int, prot int) (mem []byte, err error) {
	if size == 0 {
		return
	}

	return syscall.Mmap(-1, 0, size, prot, syscall.MAP_SHARED|syscall.MAP_ANONYMOUS|syscall.MAP_NORESERVE)
}
