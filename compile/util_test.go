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
	"testing"

	"github.com/tsavola/wag/internal/data"
	"github.com/tsavola/wag/internal/test/runner"
	"github.com/tsavola/wag/object/file"
	"github.com/tsavola/wag/wa"
)

const (
	binDir = "../testdata/wabt/bin"

	dumpWAST = false
	dumpWASM = false
)

type variadicImportResolver interface {
	ResolveVariadicFunc(module, field string, sig wa.FuncType) (variadic bool, index int, err error)
	ResolveGlobal(module, field string, t wa.Type) (init uint64, err error)
}

func bindVariadicImports(mod *Module, reso variadicImportResolver) {
	var err error

	for i := range mod.m.ImportFuncs {
		imp := &mod.m.ImportFuncs[i]
		imp.Variadic, imp.VecIndex, err = reso.ResolveVariadicFunc(mod.ImportFunc(i))
		if err != nil {
			panic(err)
		}
	}

	for i := range mod.m.ImportGlobals {
		mod.m.Globals[i].Init, err = reso.ResolveGlobal(mod.ImportGlobal(i))
		if err != nil {
			panic(err)
		}
	}
}

func findNiladicEntryFunc(mod Module, name string) (funcIndex uint32) {
	funcIndex, sig, found := mod.ExportFunc(name)
	if !found {
		panic("entry function not found")
	}
	if len(sig.Params) != 0 {
		panic("entry function has parameters")
	}
	return
}

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

func initFuzzCorpus(t *testing.T, filename string, r io.Reader) {
	t.Helper()

	if dir := os.Getenv("WAG_TEST_INIT_FUZZ_CORPUS"); dir != "" {
		data, err := ioutil.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		filename = path.Join(dir, filename)

		if err := ioutil.WriteFile(filename, data, 0666); err != nil {
			t.Fatal(err)
		}

		t.Skip("initializing fuzz corpus")
	}
}

func dumpExecutable(filename string, p *runner.Program, globalsMemory data.Buffer, memoryOffset int) {
	runtime, runtimeAddr := runner.ObjectRuntime()
	entryAddr, entryArgs := p.GetStackEntry()

	objFile := file.File{
		Runtime:       runtime,
		RuntimeAddr:   runtimeAddr,
		EntryAddr:     entryAddr,
		EntryArgs:     entryArgs,
		Text:          p.Text,
		GlobalsMemory: globalsMemory.Bytes(),
		MemoryOffset:  memoryOffset,
	}

	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	defer func() {
		if err != nil {
			os.Remove(filename)
		}
	}()

	_, err = objFile.WriteTo(f)
	if err != nil {
		panic(err)
	}

	fi, err := f.Stat()
	if err != nil {
		panic(err)
	}

	mode := fi.Mode()
	mode |= (mode & 0444) >> 2 // copy readable bits to executable bits

	err = f.Chmod(mode)
	if err != nil {
		panic(err)
	}
}
