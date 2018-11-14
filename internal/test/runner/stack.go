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

	"github.com/tsavola/wag/section"
	"github.com/tsavola/wag/wa"
)

func (p *Program) findCaller(retAddr int32) (num int, initial, ok bool) {
	if len(p.DebugMap.FuncAddrs) == 0 {
		return
	}

	firstFuncAddr := p.DebugMap.FuncAddrs[0]
	if retAddr > 0 && retAddr < int32(firstFuncAddr) {
		initial = true
		ok = true
		return
	}

	num = sort.Search(len(p.DebugMap.FuncAddrs), func(i int) bool {
		var funcEndAddr int32

		i++
		if i == len(p.DebugMap.FuncAddrs) {
			funcEndAddr = int32(len(p.Text))
		} else {
			funcEndAddr = int32(p.DebugMap.FuncAddrs[i])
		}

		return retAddr <= funcEndAddr
	})

	if num < len(p.DebugMap.FuncAddrs) {
		ok = true
	}
	return
}

type callSite struct {
	index       uint64
	stackOffset int
}

func (p *Program) CallSites() map[int]callSite {
	if p.callSites == nil {
		p.callSites = make(map[int]callSite)
		for i, site := range p.DebugMap.CallSites {
			p.callSites[int(site.RetAddr)] = callSite{
				uint64(i),
				int(site.StackOffset),
			}
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

		_, initial, ok := p.findCaller(int32(retAddr))
		if !ok {
			err = errors.New("function not found for return address")
			return
		}

		//Q("tracing stack:", depth, initial)
		//Q("tracing stack:", depth, site.index)
		//Q("tracing stack:", depth, site.stackOffset)

		if initial {
			if site.stackOffset != 0 && (site.stackOffset < 8 || (site.stackOffset&7) != 0) {
				err = errors.New("invalid stack offset")
				return
			}
		} else {
			if site.stackOffset < 8 || (site.stackOffset&7) != 0 {
				err = errors.New("invalid stack offset")
				return
			}
		}

		byteOrder.PutUint64(buf[:8], site.index) // native address -> portable index

		if initial {
			buf = buf[:0]
			return
		}

		buf = buf[site.stackOffset:]

		//Q("tracing stack (continuing to next level):", depth)
		//depth++
	}

	err = errors.New("ran out of stack before reaching initial function call")
	return
}

func (p *Program) writeStacktraceTo(w io.Writer, funcs []wa.FuncType, ns *section.NameSection, stack []byte) (err error) {
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

		funcNum, start, ok := p.findCaller(int32(retAddr))
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

		if ns != nil && funcNum < len(ns.FuncNames) {
			name = ns.FuncNames[funcNum].FuncName
			localNames = ns.FuncNames[funcNum].LocalNames
		} else {
			name = fmt.Sprintf("func-%d", funcNum)
		}

		var sigStr string

		if funcNum < len(funcs) {
			sigStr = funcSigWithNames(funcs[funcNum], localNames)
		}

		fmt.Fprintf(w, "#%d  %s%s\n", depth, name, sigStr)
	}

	if len(stack) != 0 {
		fmt.Fprintf(w, "#%d  <%d bytes of untraced stack>\n", depth, len(stack))
	}
	return
}

func (r *Runner) WriteStacktraceTo(w io.Writer, funcs []wa.FuncType, ns *section.NameSection) (err error) {
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

	return r.prog.writeStacktraceTo(w, funcs, ns, r.stack[unused:])
}

func funcSigWithNames(f wa.FuncType, localNames []string) (s string) {
	s = "("
	for i, t := range f.Params {
		if i > 0 {
			s += ", "
		}
		if i < len(localNames) {
			s += localNames[i] + " "
		}
		s += t.String()
	}
	s += ")"
	if f.Result != wa.Void {
		s += " " + f.Result.String()
	}
	return
}
