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

func run(text []byte, initialMemorySize int, memory, stack []byte, stackOffset, resume, arg, slaveFd int) (result int32, trap int, currentMemorySize int, stackPtr uintptr)

func importSnapshot() int64
func importSpectestPrint() int64

const (
	memoryIncrementSize = 65536
)

var (
	systemPageSize = syscall.Getpagesize()
)

type Buffer struct {
	Imports map[string]map[string]imports.Function
	ROData  []byte

	sealed bool
}

func NewBuffer(maxRODataSize int) (b *Buffer, err error) {
	b = &Buffer{
		Imports: map[string]map[string]imports.Function{
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
		},
	}

	b.ROData, err = makeMemory(maxRODataSize, syscall.MAP_32BIT)
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
	if b.ROData != nil {
		err = syscall.Mprotect(b.ROData, syscall.PROT_READ)
		if err != nil {
			return
		}
	}

	b.sealed = true
	return
}

func (b *Buffer) Close() (first error) {
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

	text      []byte
	globals   []byte
	data      []byte
	funcMap   []byte
	callMap   []byte
	funcTypes []types.Function
	funcNames []string

	funcAddrs map[int]int
	callSites map[int]callSite
}

func (b *Buffer) NewProgram(text, globals, data, funcMap, callMap []byte, funcTypes []types.Function, funcNames []string) (p *Program, err error) {
	if !b.sealed {
		err = errors.New("buffer has not been sealed")
		return
	}

	p = &Program{
		buf:       b,
		globals:   globals,
		data:      data,
		funcMap:   funcMap,
		callMap:   callMap,
		funcTypes: funcTypes,
		funcNames: funcNames,
	}

	p.text, err = makeMemoryCopy(text, syscall.PROT_EXEC|syscall.PROT_READ, syscall.MAP_32BIT)
	if err != nil {
		p.Close()
		return
	}

	return
}

func (p *Program) Close() (first error) {
	if p.text != nil {
		if err := syscall.Munmap(p.text); err != nil && first == nil {
			first = err
		}
	}

	return
}

func (p *Program) getText() []byte {
	return p.text
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

	r.globalsMemory, err = makeMemory(r.globalsOffset+growMemorySize, 0)
	if err != nil {
		r.Close()
		return
	}

	r.stack, err = makeMemory(stackSize, 0)
	if err != nil {
		r.Close()
		return
	}

	r.initData()
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
	stackState := r.prog.getStack()
	resume := len(stackState) // boolean
	stackOffset := len(r.stack) - len(stackState)
	copy(r.stack[stackOffset:], stackState)

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return
	}

	printed := make(chan struct{})

	defer func() {
		syscall.Close(fds[1])
		<-printed
	}()

	go func() {
		defer close(printed)
		r.slave(fds[0], sigs, printer)
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	memory := r.globalsMemory[r.memoryOffset:]

	result, trap, memorySize, stackPtr := run(r.prog.getText(), r.memorySize, memory, r.stack, stackOffset, resume, arg, fds[1])

	r.memorySize = memorySize
	r.lastTrap = traps.Id(trap)
	r.lastStackPtr = stackPtr

	if trap != 0 {
		err = r.lastTrap
	}
	return
}

/*
func (r *Runner) ResetMemory() {
	r.initData()

	tail := r.globalsMemory[r.memoryOffset+len(r.prog.data):]
	for i := range tail {
		tail[i] = 0
	}

	// TODO: reset memorySize
}
*/

func (r *Runner) initData() {
	copy(r.globalsMemory[r.globalsOffset:], r.prog.getGlobals())
	copy(r.globalsMemory[r.memoryOffset:], r.prog.getData())
}

func makeMemory(size int, extraFlags int) (mem []byte, err error) {
	if size == 0 {
		return
	}

	return syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|extraFlags)
}

func makeMemoryCopy(buf []byte, prot, flags int) (mem []byte, err error) {
	mem, err = makeMemory(len(buf), flags)
	if err != nil {
		return
	}

	copy(mem, buf)

	if mem == nil {
		return
	}

	err = syscall.Mprotect(mem, prot)
	if err != nil {
		syscall.Munmap(mem)
	}
	return
}
