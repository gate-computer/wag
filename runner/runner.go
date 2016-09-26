package runner

import (
	"errors"
	"io"
	"reflect"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/tsavola/wag/internal/imports"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/traps"
)

func run(text, memory, stack []byte, arg, printFd int) (result int32, trap int, stackPtr uintptr)
func importSpectestPrint() int64

var (
	pageSize = syscall.Getpagesize()
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

type Program struct {
	buf *Buffer

	text    []byte
	globals []byte
	data    []byte
	funcMap []byte
	callMap []byte

	funcAddrs        map[int]int
	callStackOffsets map[int]int
}

func (b *Buffer) NewProgram(text, globals, data, funcMap, callMap []byte) (p *Program, err error) {
	if !b.sealed {
		err = errors.New("buffer has not been sealed")
		return
	}

	p = &Program{
		buf:     b,
		globals: globals,
		data:    data,
		funcMap: funcMap,
		callMap: callMap,
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

type Runner struct {
	prog *Program

	globalsOffset    int
	memoryOffset     int
	globalsAndMemory []byte
	stack            []byte

	dirty        bool
	lastTrap     traps.Id
	lastStackPtr uintptr
}

func (p *Program) NewRunner(memorySize, stackSize int) (r *Runner, err error) {
	if memorySize < len(p.data) {
		err = errors.New("data does not fit in memory")
		return
	}

	padding := (pageSize - len(p.globals)) & (pageSize - 1)

	r = &Runner{
		prog:          p,
		globalsOffset: padding,
		memoryOffset:  padding + len(p.globals),
	}

	r.globalsAndMemory, err = makeMemory(r.globalsOffset+memorySize, 0)
	if err != nil {
		r.Close()
		return
	}

	r.stack, err = makeMemory(stackSize, 0)
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

	if r.globalsAndMemory != nil {
		if err := syscall.Munmap(r.globalsAndMemory); err != nil && first == nil {
			first = err
		}
	}

	return
}

func (r *Runner) Run(arg int, sigs map[uint64]types.Function, printer io.Writer) (result int32, err error) {
	copy(r.globalsAndMemory[r.globalsOffset:], r.prog.globals)
	copy(r.globalsAndMemory[r.memoryOffset:], r.prog.data)

	memory := r.globalsAndMemory[r.memoryOffset:]
	tail := memory[len(r.prog.data):]

	if r.dirty {
		for i := range tail {
			tail[i] = 0
		}
	}

	pipe := make([]int, 2)

	err = syscall.Pipe2(pipe, syscall.O_CLOEXEC)
	if err != nil {
		return
	}

	printed := make(chan struct{})

	defer func() {
		syscall.Close(pipe[1])
		<-printed
	}()

	go func() {
		defer close(printed)
		spectestPrintServer(pipe[0], sigs, printer)
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result, trap, stackPtr := run(r.prog.text, memory, r.stack, arg, pipe[1])

	r.dirty = true
	r.lastTrap = traps.Id(trap)
	r.lastStackPtr = stackPtr

	if trap != 0 {
		err = r.lastTrap
	}
	return
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