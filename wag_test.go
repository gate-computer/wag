package wag

import (
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

type fun func() int32

type startFunc struct {
	f *fun
}

type startFuncPtr *startFunc

func TestHelloWorld(t *testing.T) {
	test(t, "testdata/test.wast")
}

func test(t *testing.T, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	m := loadModule(data)
	t.Logf("module = %v", m)

	for _, f := range m.Functions {
		t.Logf("function = %#v", f)
	}

	binary := m.GenCode()

	f, err := os.Create("testdata/code")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.Write(binary); err != nil {
		t.Fatal(err)
	}

	dump := exec.Command("objdump", "-D", "-bbinary", "-mi386:x86-64", "testdata/code")
	dump.Stdout = os.Stdout
	dump.Stderr = os.Stderr

	if err := dump.Run(); err != nil {
		t.Fatal(err)
	}

	cc := exec.Command("cc", "-g", "-o", "testdata/exec", "testdata/exec.c")
	cc.Stdout = os.Stdout
	cc.Stderr = os.Stderr

	if err := cc.Run(); err != nil {
		t.Fatal(err)
	}

	// exec := exec.Command("gdb", "-ex", "run", "-ex", "bt", "-ex", "quit", "--args", "testdata/exec", "testdata/code")
	exec := exec.Command("testdata/exec", "testdata/code")
	exec.Stdin = f
	exec.Stdout = os.Stdout
	exec.Stderr = os.Stderr

	if err := exec.Run(); err != nil {
		t.Fatal(err)
	}
}
