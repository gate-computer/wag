// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wat

import (
	"io"
	"io/ioutil"
	"os"
	"os/exec"
)

const (
	dumpWAT  = false
	dumpWASM = false
)

func ToWasm(expString []byte, quiet bool) io.ReadCloser {
	wasm2wat := os.Getenv("WASM2WAT")
	if wasm2wat == "" {
		wasm2wat = "wasm2wat"
	}
	wat2wasm := os.Getenv("WAT2WASM")
	if wat2wasm == "" {
		wat2wasm = "wat2wasm"
	}

	f, err := ioutil.TempFile("", "")
	if err != nil {
		panic(err)
	}
	_, err = f.Write(expString)
	f.Close()
	if err != nil {
		os.Remove(f.Name())
		panic(err)
	}

	if dumpWAT {
		f3, err := ioutil.TempFile("", "")
		if err != nil {
			panic(err)
		}
		defer f3.Close()

		cmd3 := exec.Command(wat2wasm, "--no-check", "-o", f3.Name(), f.Name())
		cmd3.Stdout = os.Stdout
		cmd3.Stderr = os.Stderr
		if err := cmd3.Run(); err != nil {
			os.Remove(f3.Name())
			os.Remove(f.Name())
			panic(err)
		}

		cmd2 := exec.Command(wasm2wat, "--no-check", "-o", "/dev/stdout", f3.Name())
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
		if err := cmd2.Run(); err != nil {
			os.Remove(f.Name())
			panic(err)
		}
	}

	if dumpWASM {
		cmd := exec.Command(wat2wasm, "--no-check", "-v", f.Name())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			os.Remove(f.Name())
			panic(err)
		}
	}

	f2, err := ioutil.TempFile("", "")
	if err != nil {
		os.Remove(f.Name())
		panic(err)
	}
	os.Remove(f2.Name())

	cmd := exec.Command(wat2wasm, "--debug-names", "--no-check", "-o", "/dev/stdout", f.Name())
	cmd.Stdout = f2
	if !quiet {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		f2.Close()
		os.Remove(f.Name())
		panic(err)
	}

	if _, err := f2.Seek(0, io.SeekStart); err != nil {
		f2.Close()
		os.Remove(f.Name())
		panic(err)
	}

	return f2
}
