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
	"github.com/tsavola/wag/sections"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/types"
	"github.com/tsavola/wag/wasm"
)

func setRunArg(arg int64)

func run(text []byte, initialMemorySize int, memoryAddr, growMemorySize uintptr, stack []byte, stackOffset, resumeResult, slaveFd int) (trap uint64, currentMemorySize int, stackPtr uintptr)

func importGetArg() uint64
func importSnapshot() uint64
func importSpectestPrint() uint64
func importPutns() uint64

var (
	systemPageSize = syscall.Getpagesize()
)

var importFunctions = map[string]map[string]imports.Function{
	"spectest": {
		"print": imports.Function{
			Variadic: true,
			AbsAddr:  importSpectestPrint(),
		},
	},
	"wag": {
		"get_arg": imports.Function{
			Function: types.Function{
				Result: types.I64,
			},
			AbsAddr: importGetArg(),
		},
		"snapshot": imports.Function{
			Function: types.Function{
				Result: types.I32,
			},
			AbsAddr: importSnapshot(),
		},
	},
	"env": {
		"putns": imports.Function{
			Function: types.Function{
				Args: []types.T{types.I32, types.I32},
			},
			AbsAddr: importPutns(),
		},
	},
}

type env struct{}

func (env) ImportFunction(module, field string, sig types.Function) (variadic bool, absAddr uint64, err error) {
	f, found := importFunctions[module][field]
	if !found {
		err = fmt.Errorf("imported function not found: %s %s %s", module, field, sig)
		return
	}

	if !f.Implements(sig) {
		err = fmt.Errorf("imported function %s %s has incompatible signature: %s", module, field, sig)
		return
	}

	variadic = f.Variadic
	absAddr = f.AbsAddr
	return
}

func (env) ImportGlobal(module, field string, t types.T) (valueBits uint64, err error) {
	switch module {
	case "spectest":
		switch field {
		case "global":
			return
		}
	}

	err = fmt.Errorf("imported %s global not found: %s %s", t, module, field)
	return
}

var Env env

type runnable interface {
	getText() []byte
	getData() ([]byte, int)
	getStack() []byte
	writeStacktraceTo(w io.Writer, funcSigs []types.Function, ns *sections.NameSection, stack []byte) error
	exportStack(native []byte) (portable []byte, err error)
}

type Program struct {
	Text   []byte
	ROData []byte

	data         []byte
	memoryOffset int

	funcMap []byte
	callMap []byte

	funcAddrs map[int]int
	callSites map[int]callSite
}

func NewProgram(maxTextSize, maxRODataSize int) (p *Program, err error) {
	p = &Program{}

	p.Text, err = makeMemory(maxTextSize, syscall.PROT_EXEC, syscall.MAP_32BIT)
	if err != nil {
		p.Close()
		return
	}

	p.ROData, err = makeMemory(maxRODataSize, 0, syscall.MAP_32BIT)
	if err != nil {
		p.Close()
		return
	}

	return
}

func (p *Program) RODataAddr() int32 {
	addr := (*reflect.SliceHeader)(unsafe.Pointer(&p.ROData)).Data
	if addr == 0 || addr > 0x7fffffff-uintptr(len(p.ROData)) {
		panic("sanity check failed")
	}
	return int32(addr)
}

func (p *Program) SetData(data []byte, memoryOffset int) {
	p.data = data
	p.memoryOffset = memoryOffset
}

func (p *Program) SetFunctionMap(funcMap []byte) {
	p.funcMap = funcMap
}

func (p *Program) SetCallMap(callMap []byte) {
	p.callMap = callMap
}

func (p *Program) Seal() (err error) {
	if p.Text != nil {
		err = syscall.Mprotect(p.Text, syscall.PROT_EXEC)
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
	memorySize    wasm.MemorySize
	stack         []byte

	lastTrap     traps.Id
	lastStackPtr uintptr

	Snapshots []*Snapshot
}

func (p *Program) NewRunner(initMemorySize, growMemorySize wasm.MemorySize, stackSize int) (r *Runner, err error) {
	return newRunner(p, initMemorySize, growMemorySize, stackSize)
}

func newRunner(prog runnable, initMemorySize, growMemorySize wasm.MemorySize, stackSize int) (r *Runner, err error) {
	if (initMemorySize & (wasm.Page - 1)) != 0 {
		err = fmt.Errorf("initial memory size is not multiple of %d", wasm.Page)
		return
	}
	if (growMemorySize & (wasm.Page - 1)) != 0 {
		err = fmt.Errorf("memory growth limit is not multiple of %d", wasm.Page)
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

func (r *Runner) Run(arg int64, sigs []types.Function, printer io.Writer) (result int32, err error) {
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
	sigs    []types.Function
	printer io.Writer

	cont chan struct{}
	done chan struct{}

	result int32
	err    error
}

func (r *Runner) NewExecutor(sigs []types.Function, printer io.Writer) (e *Executor, trigger chan<- struct{}) {
	e = &Executor{
		runner:  r,
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

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	setRunArg(e.arg)

	globalsMemoryAddr := (*reflect.SliceHeader)(unsafe.Pointer(&e.runner.globalsMemory)).Data
	memoryAddr := globalsMemoryAddr + uintptr(e.runner.memoryOffset)
	growMemorySize := len(e.runner.globalsMemory) - e.runner.memoryOffset

	trap, memorySize, stackPtr := run(e.runner.prog.getText(), int(e.runner.memorySize), memoryAddr, uintptr(growMemorySize), e.runner.stack, stackOffset, resumeResult, fds[1])

	e.runner.memorySize = wasm.MemorySize(memorySize)
	e.runner.lastTrap = traps.Id(uint32(trap))
	e.runner.lastStackPtr = stackPtr

	if e.runner.lastTrap == traps.Exit {
		e.result = int32(uint32(trap >> 32))
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
