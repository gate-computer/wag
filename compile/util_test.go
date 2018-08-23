// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
)

const (
	binDir = "../testdata/wabt/bin"

	dumpWAST = false
	dumpWASM = false
)

func wast2wasm(expString []byte, quiet bool) io.ReadCloser {
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

	if dumpWAST {
		f3, err := ioutil.TempFile("", "")
		if err != nil {
			panic(err)
		}
		defer f3.Close()

		cmd3 := exec.Command(path.Join(binDir, "wat2wasm"), "--no-check", "-o", f3.Name(), f.Name())
		cmd3.Stdout = os.Stdout
		cmd3.Stderr = os.Stderr
		if err := cmd3.Run(); err != nil {
			os.Remove(f3.Name())
			os.Remove(f.Name())
			panic(err)
		}

		cmd2 := exec.Command(path.Join(binDir, "wasm2wat"), "--no-check", "-o", "/dev/stdout", f3.Name())
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
		if err := cmd2.Run(); err != nil {
			os.Remove(f.Name())
			panic(err)
		}
	}

	if dumpWASM {
		cmd := exec.Command(path.Join(binDir, "wat2wasm"), "--no-check", "-v", f.Name())
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

	cmd := exec.Command(path.Join(binDir, "wat2wasm"), "--debug-names", "--no-check", "-o", "/dev/stdout", f.Name())
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

func writeBin(m *Module, sourceFilename string) error {
	roDataSize := (len(m.ROData()) + 4095) &^ 4095

	buf := make([]byte, roDataSize+len(m.Text()))
	copy(buf, m.ROData())
	copy(buf[roDataSize:], m.Text())

	filename := sourceFilename
	if i := strings.LastIndex(filename, "."); i > 0 {
		filename = filename[:i]
	}
	filename += ".bin"

	return ioutil.WriteFile(filename, buf, 0644)
}
