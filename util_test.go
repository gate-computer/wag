package wag

import (
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
)

const (
	binDir = "testdata/wabt/out"

	dumpWAST = false
	dumpWASM = false
	dumpText = false
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

		cmd3 := exec.Command(path.Join(binDir, "wast2wasm"), "-o", f3.Name(), f.Name())
		cmd3.Stdout = os.Stdout
		cmd3.Stderr = os.Stderr
		if err := cmd3.Run(); err != nil {
			os.Remove(f3.Name())
			os.Remove(f.Name())
			panic(err)
		}

		cmd2 := exec.Command(path.Join(binDir, "wasm2wast"), "-o", "/dev/stdout", f3.Name())
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
		if err := cmd2.Run(); err != nil {
			os.Remove(f.Name())
			panic(err)
		}
	}

	if dumpWASM {
		cmd := exec.Command(path.Join(binDir, "wast2wasm"), "-v", f.Name())
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

	cmd := exec.Command(path.Join(binDir, "wast2wasm"), "-o", "/dev/stdout", f.Name())
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

func objdump(text []byte) {
	if dumpText {
		f, err := ioutil.TempFile("", "")
		if err != nil {
			panic(err)
		}
		_, err = f.Write(text)
		f.Close()
		defer os.Remove(f.Name())
		if err != nil {
			panic(err)
		}

		cmd := exec.Command("objdump", "-D", "-bbinary", "-mi386:x86-64", f.Name())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			panic(err)
		}
	}
}
