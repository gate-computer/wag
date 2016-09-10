package runner

import (
	"syscall"

	"github.com/tsavola/wag/traps"
)

func run(text, roData, stack []byte, arg int) (result int32, trap int)

type Program struct {
	text   []byte
	roData []byte

	dataProto []byte
	bssSize   int
}

func NewProgram(text, roData, data []byte, bssSize int) (p *Program, err error) {
	p = &Program{
		dataProto: data,
		bssSize:   bssSize,
	}

	p.text, err = makeMemoryCopy(text, syscall.PROT_EXEC|syscall.PROT_READ)
	if err != nil {
		p.Close()
		return
	}

	p.roData, err = makeMemoryCopy(roData, syscall.PROT_READ)
	if err != nil {
		p.Close()
		return
	}

	return
}

func (p *Program) Close() (first error) {
	if p.roData != nil {
		if err := syscall.Munmap(p.roData); err != nil && first == nil {
			first = err
		}
	}

	if p.text != nil {
		if err := syscall.Munmap(p.text); err != nil && first == nil {
			first = err
		}
	}

	return
}

type Runner struct {
	prog *Program

	data  []byte
	bss   []byte
	stack []byte
}

func (p *Program) NewRunner(stackSize int) (r *Runner, err error) {
	r = &Runner{prog: p}

	r.data, err = makeMemory(len(p.dataProto))
	if err != nil {
		r.Close()
		return
	}

	r.bss, err = makeMemory(p.bssSize)
	if err != nil {
		r.Close()
		return
	}

	r.stack, err = makeMemory(stackSize)
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

	if r.bss != nil {
		if err := syscall.Munmap(r.bss); err != nil && first == nil {
			first = err
		}
	}

	if r.data != nil {
		if err := syscall.Munmap(r.data); err != nil && first == nil {
			first = err
		}
	}

	return
}

func (r *Runner) Run(arg int) (result int32, err error) {
	copy(r.data, r.prog.dataProto)

	if len(r.bss) < cap(r.bss) { // dirty?
		r.bss = r.bss[:cap(r.bss)]
		for i := range r.bss {
			r.bss[i] = 0
		}
	}

	result, trap := run(r.prog.text, r.prog.roData, r.stack, arg)
	if trap != 0 {
		err = traps.Id(trap)
	}

	r.bss = r.bss[:0] // flag it as dirty

	return
}

func makeMemory(size int) (mem []byte, err error) {
	if size == 0 {
		return
	}

	return syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
}

func makeMemoryCopy(buf []byte, prot int) (mem []byte, err error) {
	mem, err = makeMemory(len(buf))
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
