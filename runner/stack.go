package runner

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"unsafe"
)

func (p *Program) findCaller(retAddr uint32) (num int, init, ok bool) {
	count := len(p.funcMap) / 4
	if count == 0 {
		return
	}

	firstFuncAddr := byteOrder.Uint32(p.funcMap[:4])
	if retAddr > 0 && retAddr < firstFuncAddr {
		init = true
		ok = true
		return
	}

	num = sort.Search(count, func(i int) bool {
		var funcEndAddr uint32

		i++
		if i == count {
			funcEndAddr = uint32(len(p.text))
		} else {
			funcEndAddr = byteOrder.Uint32(p.funcMap[i*4 : (i+1)*4])
		}

		return retAddr <= funcEndAddr
	})

	if num < count {
		ok = true
	}
	return
}

func (p *Program) FuncAddrs() map[int]int {
	if p.funcAddrs == nil {
		p.funcAddrs = make(map[int]int)

		buf := p.funcMap
		for i := 0; len(buf) > 0; i++ {
			p.funcAddrs[i] = int(byteOrder.Uint32(buf[:4]))
			buf = buf[4:]
		}
	}

	return p.funcAddrs
}

type callSite struct {
	index       uint64
	stackOffset int
}

func (p *Program) CallSites() map[int]callSite {
	if p.callSites == nil {
		p.callSites = make(map[int]callSite)

		buf := p.callMap
		for i := 0; len(buf) > 0; i++ {
			entry := byteOrder.Uint64(buf[:8])
			buf = buf[8:]

			addr := int(uint32(entry))
			stackOffset := int(entry >> 32)

			p.callSites[addr] = callSite{uint64(i), stackOffset}
		}
	}

	return p.callSites
}

func (p *Program) exportStack(native []byte) (portable []byte, err error) {
	portable = make([]byte, len(native))
	copy(portable, native)

	textAddr := uint64((*reflect.SliceHeader)(unsafe.Pointer(&p.text)).Data)
	callSites := p.CallSites()

	buf := portable[:len(portable)-8] // drop test arg

	for len(buf) > 0 {
		absoluteRetAddr := byteOrder.Uint64(buf[:8])

		retAddr := absoluteRetAddr - textAddr
		if retAddr > 0x7ffffffe {
			err = errors.New("absolute return address is not in text section")
			return
		}

		site, found := callSites[int(retAddr)]
		if !found {
			err = errors.New("unknown absolute return address")
			return
		}
		if site.stackOffset < 8 || (site.stackOffset&7) != 0 {
			err = errors.New("invalid stack offset")
			return
		}

		byteOrder.PutUint64(buf[:8], site.index) // native address -> portable index

		buf = buf[site.stackOffset:]

		_, init, ok := p.findCaller(uint32(retAddr))
		if !ok {
			err = errors.New("function not found for absolute return address")
			return
		}
		if init {
			if len(buf) != 0 {
				err = errors.New("excess data remains at end of stack")
			}
			return
		}
	}

	err = errors.New("ran out of stack before reaching initial function")
	return
}

func (p *Program) writeStacktraceTo(w io.Writer, stack []byte) (err error) {
	textAddr := uint64((*reflect.SliceHeader)(unsafe.Pointer(&p.text)).Data)
	callSites := p.CallSites()

	stack = stack[:len(stack)-8] // drop test arg

	for depth := 1; len(stack) > 0; depth++ {
		absoluteRetAddr := byteOrder.Uint64(stack[:8])

		retAddr := absoluteRetAddr - textAddr
		if retAddr > 0x7ffffffe {
			fmt.Fprintf(w, "#%d  <absolute return address 0x%x is not in text section>\n", depth, absoluteRetAddr)
			fmt.Fprintf(w, "(%d bytes of untraced stack)\n", len(stack)-8)
			break
		}

		site, found := callSites[int(retAddr)]
		if !found {
			fmt.Fprintf(w, "#%d  <unknown absolute return address 0x%x>\n", depth, absoluteRetAddr)
		}
		if site.stackOffset < 8 || (site.stackOffset&7) != 0 {
			fmt.Fprintf(w, "#%d  <invalid stack offset %d>\n", depth, site.stackOffset)
			break
		}

		stack = stack[site.stackOffset:]

		funcNum, init, ok := p.findCaller(uint32(retAddr))
		if !ok {
			fmt.Fprintf(w, "#%d  <function not found for return address 0x%x>\n", depth, retAddr)
			break
		}
		if init {
			break
		}

		fmt.Fprintf(w, "#%d  %s %s\n", depth, p.funcNames[funcNum], p.funcTypes[funcNum])
	}

	if len(stack) != 0 {
		fmt.Fprintf(w, "warning: %d bytes of untraced stack remains\n", len(stack))
	}

	return
}

func (r *Runner) WriteStacktraceTo(w io.Writer) (err error) {
	if r.lastTrap != 0 {
		fmt.Fprintf(w, "#0  %s\n", r.lastTrap)
	}

	if r.lastStackPtr == 0 {
		return
	}

	stackLimit := (*reflect.SliceHeader)(unsafe.Pointer(&r.stack)).Data
	unused := uintptr(r.lastStackPtr) - stackLimit
	if unused < 0 || unused > uintptr(len(r.stack)) {
		err = errors.New("stack pointer out of range")
		return
	}

	return r.prog.writeStacktraceTo(w, r.stack[unused:])
}
