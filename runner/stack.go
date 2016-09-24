package runner

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"unsafe"

	"github.com/tsavola/wag/internal/types"
)

func (p *Program) findCaller(callSite uint32) (num int, ok bool) {
	count := len(p.funcMap) / 4

	num = sort.Search(count, func(i int) bool {
		var funcEndAddr uint32

		i++
		if i == count {
			funcEndAddr = uint32(len(p.text))
		} else {
			funcEndAddr = byteOrder.Uint32(p.funcMap[i*4 : (i+1)*4])
		}

		return callSite < funcEndAddr
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

func (p *Program) CallStackOffsets() map[int]int {
	if p.callStackOffsets == nil {
		p.callStackOffsets = make(map[int]int)

		buf := p.callMap
		for i := 0; len(buf) > 0; i++ {
			entry := byteOrder.Uint64(buf[:8])
			buf = buf[8:]

			addr := int(uint32(entry))
			stackOffset := int(entry >> 32)

			p.callStackOffsets[addr] = stackOffset
		}
	}

	return p.callStackOffsets
}

func (r *Runner) WriteStacktraceTo(w io.Writer, funcTypes []types.Function, funcNames []string) (err error) {
	if r.lastTrap != 0 {
		fmt.Fprintf(w, "#0  %s\n", r.lastTrap)
	}

	if r.lastStackPtr == 0 {
		return
	}

	textAddr := uint64((*reflect.SliceHeader)(unsafe.Pointer(&r.prog.text)).Data)

	stackLimit := (*reflect.SliceHeader)(unsafe.Pointer(&r.stack)).Data
	unused := uintptr(r.lastStackPtr) - stackLimit
	if unused < 0 || unused > uintptr(len(r.stack)) {
		err = errors.New("stack pointer out of range")
		return
	}

	stack := r.stack[unused : len(r.stack)-8] // drop test arg
	callStackOffsets := r.prog.CallStackOffsets()

	var stackOffset int

	for depth := 1; len(stack) > 0; depth++ {
		absoluteRetAddr := byteOrder.Uint64(stack[:8])

		retAddr := absoluteRetAddr - textAddr
		if retAddr > 0x7ffffffe {
			fmt.Fprintf(w, "#%d  <absolute return address 0x%x is not in text section>\n", depth, absoluteRetAddr)
			fmt.Fprintf(w, "(%d bytes of untraced stack)\n", len(stack)-8)
			break
		}

		var found bool

		stackOffset, found = callStackOffsets[int(retAddr)]
		if !found {
			fmt.Fprintf(w, "#%d  <call site at absolute address 0x%x is unknown>\n", depth, absoluteRetAddr, retAddr)
		}
		if stackOffset == 0 {
			if len(stack) > 8 {
				fmt.Fprintf(w, "warning: %d bytes of untraced stack\n", len(stack)-8)
			}
			break
		}

		stack = stack[stackOffset:]

		funcNum, ok := r.prog.findCaller(uint32(retAddr))
		if !ok {
			fmt.Fprintf(w, "#%d  <function not found for return address 0x%x>\n", depth, retAddr)
			break
		}

		name := funcNames[funcNum]
		if name == "" {
			name = fmt.Sprintf("unnamed function #%d", funcNum)
		}

		fmt.Fprintf(w, "#%d  %s %s\n", depth, name, funcTypes[funcNum])
	}

	if stackOffset != 0 {
		fmt.Fprintf(w, "warning: stack offset of initial caller was %d\n", stackOffset)
	}

	return
}
