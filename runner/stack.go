package runner

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"unsafe"
)

func (r *Runner) WriteStacktraceTo(w io.Writer) (err error) {
	if r.trapStackPtr == 0 {
		return
	}

	stackLimit := (*reflect.SliceHeader)(unsafe.Pointer(&r.stack)).Data
	unused := uintptr(r.trapStackPtr) - stackLimit
	if unused < 0 || unused > uintptr(len(r.stack)) {
		err = errors.New("stack pointer out of range")
		return
	}

	stack := r.stack[unused:]
	fmt.Fprintf(w, "%d bytes\n", len(stack))
	return
}
