package wag

import (
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

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

	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(binary); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cmd := exec.Command("objdump", "-D", "-bbinary", "-mi386:x86-64", f.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
