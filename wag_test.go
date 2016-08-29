package wag

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/tsavola/wag/internal/sexp"
)

const (
	magic   = 0x54fd3985
	idBase  = 556231
	objdump = true
)

type fun func() int32

type startFunc struct {
	f *fun
}

type startFuncPtr *startFunc

func TestI32(t *testing.T) { test(t, "testdata/i32.wast", "i32") }
func TestI64(t *testing.T) { test(t, "testdata/i64.wast", "i64") }

var (
	execCompiled bool
)

func test(t *testing.T, filename, typeHack string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	module, data := sexp.ParsePanic(data)

	exports := make(map[string]string)

	for i := 1; i < len(module); {
		item := module[i].([]interface{})
		if item[0].(string) == "export" {
			exports[item[1].(string)] = item[2].(string)
			module = append(module[:i], module[i+1:]...)
		} else {
			i++
		}
	}

	testFunc := []interface{}{
		"func",
		"$test",
		[]interface{}{"result", "i32"},
	}

	testId := idBase

	for {
		var assert []interface{}
		assert, data = sexp.ParsePanic(data)
		if assert == nil {
			break
		}

		invoke2call(exports, assert[1:])

		name := assert[0].(string)

		var test []interface{}

		switch name {
		case "assert_return":
			test = []interface{}{
				"if",
				append([]interface{}{typeHack + ".ne"}, assert[1:]...),
				[]interface{}{
					[]interface{}{
						"return",
						[]interface{}{
							"i32.const",
							strconv.Itoa(testId),
						},
					},
				},
			}

		default:
			t.Logf("%s skipped", name)
			continue
		}

		testFunc = append(testFunc, test)
		testId++
	}

	testFunc = append(testFunc, []interface{}{
		"return",
		[]interface{}{
			"i32.const",
			strconv.Itoa(magic),
		},
	})

	module = append(module, testFunc)

	module = append(module, []interface{}{
		"start",
		"$test",
	})

	m := loadModule(module)
	binary := m.GenCode()

	f, err := os.Create("testdata/code")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.Write(binary); err != nil {
		t.Fatal(err)
	}

	if objdump {
		dump := exec.Command("objdump", "-D", "-bbinary", "-mi386:x86-64", "testdata/code")
		dump.Stdout = os.Stdout
		dump.Stderr = os.Stderr

		if err := dump.Run(); err != nil {
			t.Fatal(err)
		}
	}

	if !execCompiled {
		cc := exec.Command("cc", "-g", "-o", "testdata/exec", "testdata/exec.c")
		cc.Stdout = os.Stdout
		cc.Stderr = os.Stderr

		if err := cc.Run(); err != nil {
			t.Fatal(err)
		}

		execCompiled = true
	}

	exec := exec.Command("testdata/exec", "testdata/code")
	exec.Stdin = f
	exec.Stdout = os.Stdout
	exec.Stderr = os.Stderr

	if err := exec.Run(); err != nil {
		t.Fatal(err)
	}
}

func invoke2call(exports map[string]string, x interface{}) {
	if item, ok := x.([]interface{}); ok {
		if s, ok := item[0].(string); ok && s == "invoke" {
			name1 := item[1].(string)
			name2, found := exports[name1]
			if !found {
				panic(name1)
			}

			item[0] = "call"
			item[1] = name2
		}

		for _, e := range item {
			invoke2call(exports, e)
		}
	}
}
