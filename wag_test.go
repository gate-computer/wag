package wag

import (
	"io/ioutil"
	"testing"
)

func TestHelloWorld(t *testing.T) {
	test(t, "testsuite/hello_world.wasm")
}

func test(t *testing.T, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	m := loadModule(data)
	t.Logf("module = %v", m)

	for i := range m.Functions {
		f := &m.Functions[i]

		if f.Flags&FunctionFlagExport != 0 && len(f.Signature.ArgTypes) == 0 {
			t.Logf("function = %v", f)

			e, err := m.NewExecution()
			if err != nil {
				t.Fatal(err)
			}

			result := f.execute(e, nil)
			t.Logf("result = %v", result)
		}
	}
}
