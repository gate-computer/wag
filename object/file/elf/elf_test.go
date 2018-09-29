// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !wagamd64,!wagarm64

package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/tsavola/wag/internal/test/runner"
)

func testText() []byte

var testGlobals = []byte{
	0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 33
}

var testMemory = []byte{
	0xb9, 0x4d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 85433
}

func TestELF(t *testing.T) {
	runtime, runtimeAddr := runner.ObjectRuntime()

	text := append([]byte{}, testText()...)
	binary.LittleEndian.PutUint32(text[8:], syscall.SYS_EXIT_GROUP)

	ef := File{
		Runtime:       runtime,
		RuntimeAddr:   runtimeAddr,
		Text:          text,
		GlobalsMemory: append(append([]byte{}, testGlobals...), testMemory...),
		MemoryOffset:  len(testGlobals),
	}

	var buf bytes.Buffer

	n, err := ef.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if int(n) != buf.Len() {
		t.Errorf("WriteTo length %d != buffer length %d", n, buf.Len())
	}

	f, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if x, err := f.DWARF(); err == nil {
		t.Errorf("DWARF: %v", x)
	}

	if x, err := f.DynamicSymbols(); err == nil {
		t.Errorf("DynamicSymbols: %v", x)
	}

	if x, err := f.ImportedLibraries(); err != nil {
		t.Error(err)
	} else if len(x) != 0 {
		t.Errorf("ImportedLibraries: %v", x)
	}

	if x, err := f.Symbols(); err == nil {
		t.Errorf("Symbols: %v", x)
	}

	t.Run("Exec", func(t *testing.T) {
		f, err := ioutil.TempFile("", "")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())

		if _, err := f.Write(buf.Bytes()); err != nil {
			f.Close()
			t.Fatal(err)
		}

		if err := f.Chmod(0700); err != nil {
			f.Close()
			t.Fatal(err)
		}

		f.Close()

		output, err := exec.Command(f.Name()).CombinedOutput()
		if len(output) != 0 {
			t.Logf("Output: %s", output)
		}
		if err != nil {
			if patherr, ok := err.(*os.PathError); ok && patherr.Path == f.Name() {
				if errno, ok := patherr.Err.(syscall.Errno); ok && errno == syscall.EACCES {
					// temp file is on noexec filesystem?
					t.Skip(err)
					return
				}
			}
			t.Errorf("Error: %v", err)
		} else if len(output) != 0 {
			t.Fail()
		}
	})
}
