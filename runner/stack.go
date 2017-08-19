// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"unsafe"

	"github.com/tsavola/wag/sections"
	"github.com/tsavola/wag/types"
)

func (p *Program) findCaller(retAddr uint32) (num int, initial, ok bool) {
	count := len(p.funcMap) / 4
	if count == 0 {
		return
	}

	firstFuncAddr := byteOrder.Uint32(p.funcMap[:4])
	if retAddr > 0 && retAddr < firstFuncAddr {
		initial = true
		ok = true
		return
	}

	num = sort.Search(count, func(i int) bool {
		var funcEndAddr uint32

		i++
		if i == count {
			funcEndAddr = uint32(len(p.Text))
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

	textAddr := uint64((*reflect.SliceHeader)(unsafe.Pointer(&p.Text)).Data)
	callSites := p.CallSites()

	buf := portable

	//depth := 0
	//Q("tracing stack (begin):", depth)

	for len(buf) > 0 {
		absoluteRetAddr := byteOrder.Uint64(buf[:8])

		//Q("tracing stack:", depth, absoluteRetAddr)

		retAddr := absoluteRetAddr - textAddr
		if retAddr > 0x7ffffffe {
			err = errors.New("absolute return address is not in text section")
			return
		}

		//Q("tracing stack:", depth, retAddr)

		site, found := callSites[int(retAddr)]
		if !found {
			err = errors.New("unknown return address")
			return
		}

		_, start, ok := p.findCaller(uint32(retAddr))
		if !ok {
			err = errors.New("function not found for return address")
			return
		}

		//Q("tracing stack:", depth, start)
		//Q("tracing stack:", depth, site.index)
		//Q("tracing stack:", depth, site.stackOffset)

		if start {
			if site.stackOffset != 0 {
				err = errors.New("start function call site stack offset is not zero")
				return
			}
			if len(buf) != 8 {
				err = errors.New("start function return address is not stored at start of stack")
				return
			}
		} else {
			if site.stackOffset < 8 || (site.stackOffset&7) != 0 {
				err = errors.New("invalid stack offset")
				return
			}
		}

		byteOrder.PutUint64(buf[:8], site.index) // native address -> portable index

		if start {
			buf = buf[:0]
			return
		}

		buf = buf[site.stackOffset:]

		//Q("tracing stack (continuing to next level):", depth)
		//depth++
	}

	err = errors.New("ran out of stack before reaching start function call")
	return
}

func (p *Program) writeStacktraceTo(w io.Writer, funcSigs []types.Function, ns *sections.NameSection, stack []byte) (err error) {
	textAddr := uint64((*reflect.SliceHeader)(unsafe.Pointer(&p.Text)).Data)
	callSites := p.CallSites()

	depth := 1

	for ; len(stack) > 0; depth++ {
		absoluteRetAddr := byteOrder.Uint64(stack[:8])

		retAddr := absoluteRetAddr - textAddr
		if retAddr > 0x7ffffffe {
			fmt.Fprintf(w, "#%d  <absolute return address 0x%x is not in text section>\n", depth, absoluteRetAddr)
			return
		}

		funcNum, start, ok := p.findCaller(uint32(retAddr))
		if !ok {
			fmt.Fprintf(w, "#%d  <function not found for return address 0x%x>\n", depth, retAddr)
			return
		}

		site, found := callSites[int(retAddr)]
		if !found {
			fmt.Fprintf(w, "#%d  <unknown return address 0x%x>\n", depth, retAddr)
			return
		}

		if start {
			if site.stackOffset != 0 {
				fmt.Fprintf(w, "#%d  <start function call site stack offset is not zero>\n", depth)
			}
			if len(stack) != 8 {
				fmt.Fprintf(w, "#%d  <start function return address is not stored at start of stack>\n", depth)
			}
			return
		}

		if site.stackOffset < 8 || (site.stackOffset&7) != 0 {
			fmt.Fprintf(w, "#%d  <invalid stack offset %d>\n", depth, site.stackOffset)
			return
		}

		stack = stack[site.stackOffset:]

		var name string
		var localNames []string

		if ns != nil && funcNum < len(ns.FunctionNames) {
			name = ns.FunctionNames[funcNum].FunName
			localNames = ns.FunctionNames[funcNum].LocalNames
		} else {
			name = fmt.Sprintf("func-%d", funcNum)
		}

		var sigStr string

		if funcNum < len(funcSigs) {
			sigStr = funcSigs[funcNum].StringWithNames(localNames)
		}

		fmt.Fprintf(w, "#%d  %s%s\n", depth, name, sigStr)
	}

	if len(stack) != 0 {
		fmt.Fprintf(w, "#%d  <%d bytes of untraced stack>\n", depth, len(stack))
	}
	return
}

func (r *Runner) WriteStacktraceTo(w io.Writer, funcSigs []types.Function, ns *sections.NameSection) (err error) {
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

	return r.prog.writeStacktraceTo(w, funcSigs, ns, r.stack[unused:])
}
