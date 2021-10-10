// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"syscall"
	"unsafe"

	"gate.computer/wag/object/abi"
	"gate.computer/wag/section"
	"gate.computer/wag/wa"
)

type Snapshot struct {
	prog runnable

	data          []byte
	memoryOffset  int
	portableStack []byte
	nativeStack   []byte
}

func (r *Runner) snapshot(f io.ReadWriter, printer io.Writer) {
	fmt.Fprintln(printer, "--- snapshotting ---")

	var currentMemoryLimit uint64

	if err := binary.Read(f, byteOrder, &currentMemoryLimit); err != nil {
		panic(err)
	}

	fmt.Fprintf(printer, "current memory limit: 0x%x\n", currentMemoryLimit)

	var currentStackPtr uint64

	if err := binary.Read(f, byteOrder, &currentStackPtr); err != nil {
		panic(err)
	}

	fmt.Fprintf(printer, "current stack ptr:    0x%x\n", currentStackPtr)

	globalsMemoryAddr := (*reflect.SliceHeader)(unsafe.Pointer(&r.globalsMemory)).Data
	globalsMemorySize := currentMemoryLimit - uint64(globalsMemoryAddr)

	fmt.Fprintf(printer, "globals+memory addr:  0x%x\n", globalsMemoryAddr)

	if globalsMemorySize >= uint64(len(r.globalsMemory)) {
		panic("snapshot: memory size is out of bounds")
	}

	memorySize := globalsMemorySize - uint64(r.memoryOffset)

	if (memorySize & uint64(wa.PageSize-1)) != 0 {
		panic(fmt.Errorf("snapshot: memory size is not multiple of %d", wa.PageSize))
	}

	stackAddr := (*reflect.SliceHeader)(unsafe.Pointer(&r.stack)).Data
	stackOffset := currentStackPtr - uint64(stackAddr)

	fmt.Fprintf(printer, "stack addr:           0x%x\n", stackAddr)

	fmt.Fprintf(printer, "globals+memory size:  %d\n", globalsMemorySize)
	fmt.Fprintf(printer, "memory size:          %d\n", memorySize)
	fmt.Fprintf(printer, "stack offset:         %d\n", stackOffset)

	if stackOffset >= uint64(len(r.stack)) {
		panic("snapshot: stack pointer is out of bounds")
	}

	liveStack := r.stack[stackOffset:]

	fmt.Fprintln(printer, "stacktrace:")
	r.prog.writeStacktraceTo(printer, nil, nil, liveStack)

	portableStack, err := r.prog.exportStack(liveStack)
	if err != nil {
		panic(err)
	}

	// TODO: importStack()
	nativeStack := make([]byte, len(liveStack))
	copy(nativeStack, liveStack)

	s := &Snapshot{
		prog:          r.prog,
		data:          make([]byte, globalsMemorySize),
		memoryOffset:  r.memoryOffset,
		portableStack: portableStack,
		nativeStack:   nativeStack,
	}

	data := r.globalsMemory[:globalsMemorySize]

	if err := syscall.Mprotect(data[r.memoryOffset:], syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		panic(err)
	}

	copy(s.data, data)

	r.Snapshots = append(r.Snapshots, s)
	snapshotID := uint64(len(r.Snapshots))

	fmt.Fprintln(printer, "--- shot snapped ---")

	if err := binary.Write(f, byteOrder, &snapshotID); err != nil {
		panic(err)
	}
}

func (s *Snapshot) getText() []byte {
	return s.prog.getText()
}

func (s *Snapshot) getData() (data []byte, memoryOffset int) {
	data = s.data
	memoryOffset = s.memoryOffset
	return
}

func (s *Snapshot) getStack() []byte {
	return s.nativeStack
}

func (*Snapshot) getResume() int {
	return abi.TextAddrResume
}

func (s *Snapshot) writeStacktraceTo(w io.Writer, sigs []wa.FuncType, ns *section.NameSection, stack []byte) (err error) {
	return s.prog.writeStacktraceTo(w, sigs, ns, stack)
}

func (s *Snapshot) exportStack(native []byte) (portable []byte, err error) {
	return s.prog.exportStack(native)
}

func (s *Snapshot) NewRunner(p *Program, growMemorySize, stackSize int) (r *Runner, err error) {
	memorySize := len(s.data) - s.memoryOffset
	return newRunner(s, p, memorySize, growMemorySize, stackSize)
}
