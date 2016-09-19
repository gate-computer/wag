package runner

import (
	"errors"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/tsavola/wag/traps"
)

func run(text, linear, stack []byte, arg int) (result int32, trap int)

var (
	pageSize = syscall.Getpagesize()
)

type Buffer struct {
	ROData []byte

	sealed bool
}

func NewBuffer(maxRODataSize int) (b *Buffer, err error) {
	b = &Buffer{}

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

	text       []byte
	data       []byte
	linearSize int
}

func (b *Buffer) NewProgram(text, data []byte, linearSize int) (p *Program, err error) {
	if !b.sealed {
		err = errors.New("buffer has not been sealed")
		return
	}

	p = &Program{
		buf:        b,
		data:       data,
		linearSize: linearSize,
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

	dataOffset   int
	linearOffset int
	memory       []byte // data + linear
	stack        []byte
}

func (p *Program) NewRunner(stackSize int) (r *Runner, err error) {
	memoryPadding := (pageSize - len(p.data)) & (pageSize - 1)

	r = &Runner{
		prog:         p,
		dataOffset:   memoryPadding,
		linearOffset: memoryPadding + len(p.data),
	}

	r.memory, err = makeMemory(r.linearOffset+p.linearSize, 0)
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

	if r.memory != nil {
		if err := syscall.Munmap(r.memory); err != nil && first == nil {
			first = err
		}
	}

	return
}

func (r *Runner) Run(arg int) (result int32, err error) {
	copy(r.memory[r.dataOffset:], r.prog.data)

	linear := r.memory[r.linearOffset:cap(r.memory)]

	if len(r.memory) < cap(r.memory) { // dirty?
		for i := range linear {
			linear[i] = 0
		}
	}

	result, trap := run(r.prog.text, linear, r.stack, arg)
	if trap != 0 {
		err = traps.Id(trap)
	}

	r.memory = r.memory[:r.dataOffset+len(r.prog.data)] // flag it as dirty

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
