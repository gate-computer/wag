package wag

import (
	"encoding/binary"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/tsavola/wag/internal/sexp"
)

const (
	magic   = 0x54fd3985
	objdump = true

	sectionAlignment = 4096
)

type fun func() int32

type startFunc struct {
	f *fun
}

type startFuncPtr *startFunc

func TestFunc(t *testing.T) { test(t, "testdata/spec/ml-proto/test/func.wast") }
func TestI32(t *testing.T)  { test(t, "testdata/i32.wast") }
func TestI64(t *testing.T)  { test(t, "testdata/i64.wast") }

var (
	execCompiled bool
)

func test(t *testing.T, filename string) {
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
		[]interface{}{"param", "$arg", "i32"},
		[]interface{}{"result", "i32"},
	}

	var id int

	for {
		var assert []interface{}
		assert, data = sexp.ParsePanic(data)
		if assert == nil {
			break
		}

		assertName := assert[0].(string)

		var argCount int
		var exprType string

		for _, x := range assert[1:] {
			if expr, ok := x.([]interface{}); ok {
				argCount++

				exprName := expr[0].(string)
				if strings.Contains(exprName, ".") {
					exprType = strings.SplitN(exprName, ".", 2)[0]
					break
				}
			}
		}

		if argCount > 1 && exprType == "" {
			t.Fatalf("can't figure out type of %s", sexp.Stringify(assert, true))
		}

		invoke2call(exports, assert[1:])

		var spec []interface{}
		var test []interface{}

		switch assertName {
		case "assert_return":
			spec = []interface{}{
				"return",
				[]interface{}{"i32.const", "0"},
			}

			if argCount > 1 {
				test = []interface{}{
					"return",
					append([]interface{}{exprType + ".eq"}, assert[1:]...),
				}
			} else {
				test = append([]interface{}{"block"}, assert[1:]...)
				test = append(test, []interface{}{"return", []interface{}{"i32.const", "1"}})
			}

		case "assert_trap":
			spec = []interface{}{
				"return",
				[]interface{}{"i32.const", "1"},
			}

			test = []interface{}{
				"block",
				assert[1],
				[]interface{}{
					"return",
					[]interface{}{"i32.const", "0"},
				},
			}

		default:
			t.Logf("skipping %s", assertName)
			continue
		}

		condSpec := []interface{}{
			"if",
			[]interface{}{
				"i32.eq",
				[]interface{}{"get_local", "$arg"},
				[]interface{}{"i32.const", strconv.Itoa(0x100000 + id)},
			},
			[]interface{}{spec},
		}

		condTest := []interface{}{
			"if",
			[]interface{}{
				"i32.eq",
				[]interface{}{"get_local", "$arg"},
				[]interface{}{"i32.const", strconv.Itoa(id)},
			},
			[]interface{}{test},
		}

		testFunc = append(testFunc, condSpec)
		testFunc = append(testFunc, condTest)

		id++
	}

	testFunc = append(testFunc, []interface{}{
		"return",
		[]interface{}{
			"i32.const",
			"-1",
		},
	})

	module = append(module, testFunc)

	module = append(module, []interface{}{
		"start",
		"$test",
	})

	m := loadModule(module)
	text, roData, data, bssSize := m.Code()

	name := path.Join("testdata", strings.Replace(path.Base(filename), ".wast", ".bin", -1))

	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}

	textSize, err := writeSection(f, text)
	if err != nil {
		t.Fatal(err)
	}

	roDataSize, err := writeSection(f, roData)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := writeSection(f, data); err != nil {
		t.Fatal(err)
	}

	if err := binary.Write(f, binary.LittleEndian, textSize); err != nil {
		t.Fatal(err)
	}

	if err := binary.Write(f, binary.LittleEndian, roDataSize); err != nil {
		t.Fatal(err)
	}

	if err := binary.Write(f, binary.LittleEndian, int64(bssSize)); err != nil {
		t.Fatal(err)
	}

	if objdump {
		dump := exec.Command("objdump", "-D", "-bbinary", "-mi386:x86-64", name)
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

	// exec := exec.Command("gdb", "-ex", "run", "-ex", "bt", "-ex", "quit", "--args", "testdata/exec", name)
	exec := exec.Command("testdata/exec", name)
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
			item[0] = "call"

			if name, found := exports[item[1].(string)]; found {
				item[1] = name
			}
		}

		for _, e := range item {
			invoke2call(exports, e)
		}
	}
}

func writeSection(f *os.File, data []byte) (size int64, err error) {
	_, err = f.Write(data)
	if err != nil {
		return
	}

	size = int64(len(data))

	padding := sectionAlignment - (size & (sectionAlignment - 1))
	if padding == sectionAlignment {
		padding = 0
	}

	_, err = f.Seek(padding, io.SeekCurrent)
	if err != nil {
		return
	}

	size += padding
	return
}
