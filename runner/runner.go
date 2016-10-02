package runner

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/tsavola/wag/internal/imports"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/traps"
)

func run(text []byte, initialMemorySize int, memory, stack []byte, stackOffset, resumeResult, arg, slaveFd int) (result int32, trap int, currentMemorySize int, stackPtr uintptr)

func importSnapshot() int64
func importSpectestPrint() int64

const (
	memoryIncrementSize = 65536
)

var (
	systemPageSize = syscall.Getpagesize()
)

var Imports = map[string]map[string]imports.Function{
	"spectest": {
		"print": imports.Function{
			Variadic: true,
			Address:  importSpectestPrint(),
		},
	},
	"wag": {
		"snapshot": imports.Function{
			Function: types.Function{
				Result: types.I32,
			},
			Address: importSnapshot(),
		},
	},
}

type Buffer struct {
	Text   []byte
	ROData []byte
}

func NewBuffer(maxTextSize, maxRODataSize int) (b *Buffer, err error) {
	b = &Buffer{}

	b.Text, err = makeMemory(maxTextSize, syscall.PROT_EXEC, syscall.MAP_32BIT)
	if err != nil {
		b.Close()
		return
	}

	b.ROData, err = makeMemory(maxRODataSize, 0, syscall.MAP_32BIT)
	if err != nil {
		b.Close()
		return
	}

	return
}

func (b *Buffer) RODataAddr() int32 {
	addr := (*reflect.SliceHeader)(unsafe.Pointer(&b.ROData)).Data
	if addr == 0 || addr > 0x7fffffff-uintptr(len(b.ROData)) {
		panic("sanity check failed")
	}
	return int32(addr)
}

func (b *Buffer) Seal() (err error) {
	if b.Text != nil {
		err = syscall.Mprotect(b.Text, syscall.PROT_EXEC|syscall.PROT_READ)
		if err != nil {
			return
		}
	}

	if b.ROData != nil {
		err = syscall.Mprotect(b.ROData, syscall.PROT_READ)
		if err != nil {
			return
		}
	}

	return
}

func (b *Buffer) Close() (first error) {
	if b.Text != nil {
		if err := syscall.Munmap(b.Text); err != nil && first == nil {
			first = err
		}
	}

	if b.ROData != nil {
		if err := syscall.Munmap(b.ROData); err != nil && first == nil {
			first = err
		}
	}

	return
}

type runnable interface {
	getText() []byte
	getGlobals() []byte
	getData() []byte
	getStack() []byte
	writeStacktraceTo(w io.Writer, stack []byte) error
	exportStack(native []byte) (portable []byte, err error)
}

type Program struct {
	buf *Buffer

	globals   []byte
	data      []byte
	funcTypes []types.Function
	funcNames []string

	funcMap []byte
	callMap []byte

	funcAddrs map[int]int
	callSites map[int]callSite
}

func (b *Buffer) NewProgram(globals, data []byte, funcTypes []types.Function, funcNames []string) *Program {
	return &Program{
		buf:       b,
		globals:   globals,
		data:      data,
		funcTypes: funcTypes,
		funcNames: funcNames,
	}
}

func (p *Program) SetMaps(funcMap, callMap []byte) {
	p.funcMap = funcMap
	p.callMap = callMap
}

func (p *Program) getText() []byte {
	return p.buf.Text
}

func (p *Program) getGlobals() []byte {
	return p.globals
}

func (p *Program) getData() []byte {
	return p.data
}

func (p *Program) getStack() []byte {
	return nil
}

type Runner struct {
	prog runnable

	globalsOffset int
	memoryOffset  int
	memorySize    int
	globalsMemory []byte
	stack         []byte

	lastTrap     traps.Id
	lastStackPtr uintptr

	Snapshots []*Snapshot
}

func (p *Program) NewRunner(initMemorySize, growMemorySize, stackSize int) (r *Runner, err error) {
	return newRunner(p, initMemorySize, growMemorySize, stackSize)
}

func newRunner(prog runnable, initMemorySize, growMemorySize, stackSize int) (r *Runner, err error) {
	if (initMemorySize & (memoryIncrementSize - 1)) != 0 {
		err = fmt.Errorf("initial memory size is not multiple of %d", memoryIncrementSize)
		return
	}
	if (growMemorySize & (memoryIncrementSize - 1)) != 0 {
		err = fmt.Errorf("memory growth limit is not multiple of %d", memoryIncrementSize)
		return
	}

	if initMemorySize < len(prog.getData()) {
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

	padding := (systemPageSize - len(prog.getGlobals())) & (systemPageSize - 1)

	r = &Runner{
		prog:          prog,
		globalsOffset: padding,
		memoryOffset:  padding + len(prog.getGlobals()),
		memorySize:    initMemorySize,
	}

	r.globalsMemory, err = makeMemory(r.globalsOffset+growMemorySize, 0, 0)
	if err != nil {
		r.Close()
		return
	}

	r.stack, err = makeMemory(stackSize, 0, 0)
	if err != nil {
		r.Close()
		return
	}

	copy(r.globalsMemory[r.globalsOffset:], r.prog.getGlobals())
	copy(r.globalsMemory[r.memoryOffset:], r.prog.getData())
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

func (r *Runner) Run(arg int, sigs map[int64]types.Function, printer io.Writer) (result int32, err error) {
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

	arg     int
	sigs    map[int64]types.Function
	printer io.Writer

	cont chan struct{}
	done chan struct{}

	result int32
	err    error
}

func (r *Runner) NewExecutor(arg int, sigs map[int64]types.Function, printer io.Writer) (e *Executor, trigger chan<- struct{}) {
	e = &Executor{
		runner:  r,
		arg:     arg,
		sigs:    sigs,
		printer: printer,
		cont:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	start := make(chan struct{})

	go func() {
		<-start
		fmt.Fprintf(e.printer, "--- execution starting ---\n")
		defer close(e.done)
		e.run()
	}()

	trigger = start
	return
}

func (e *Executor) Wait() (result int32, err error) {
	fmt.Fprintf(e.printer, "--- executable complete ---\n")
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

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	memory := e.runner.globalsMemory[e.runner.memoryOffset:]

	result, trap, memorySize, stackPtr := run(e.runner.prog.getText(), e.runner.memorySize, memory, e.runner.stack, stackOffset, resumeResult, e.arg, fds[1])

	e.runner.memorySize = memorySize
	e.runner.lastTrap = traps.Id(trap)
	e.runner.lastStackPtr = stackPtr

	if trap == 0 {
		e.result = result
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
