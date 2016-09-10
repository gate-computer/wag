package wag

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tsavola/wag/internal/sexp"
	"github.com/tsavola/wag/runner"
	"github.com/tsavola/wag/traps"
)

const (
	parallel   = true
	writeBin   = false
	dumpText   = false
	dumpROData = false

	stackSize = 0x100000

	timeout = time.Second * 3
)

type fun func() int32

type startFunc struct {
	f *fun
}

type startFuncPtr *startFunc

func TestBlock(t *testing.T)       { test(t, "testdata/spec/ml-proto/test/block.wast") }
func TestBrIf(t *testing.T)        { test(t, "testdata/spec/ml-proto/test/br_if.wast") }
func TestFac(t *testing.T)         { test(t, "testdata/spec/ml-proto/test/fac.wast") }
func TestForward(t *testing.T)     { test(t, "testdata/spec/ml-proto/test/forward.wast") }
func TestFunc(t *testing.T)        { test(t, "testdata/spec/ml-proto/test/func.wast") }
func TestI32(t *testing.T)         { test(t, "testdata/i32.wast") }
func TestI64(t *testing.T)         { test(t, "testdata/i64.wast") }
func TestIntLiterals(t *testing.T) { test(t, "testdata/spec/ml-proto/test/int_literals.wast") }
func TestLabels(t *testing.T)      { test(t, "testdata/spec/ml-proto/test/labels.wast") }
func TestNop(t *testing.T)         { test(t, "testdata/spec/ml-proto/test/nop.wast") }
func TestTypecheck(t *testing.T)   { test(t, "testdata/spec/ml-proto/test/typecheck.wast") }

func test(t *testing.T, filename string) {
	if parallel {
		t.Parallel()
	}

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

	var idCount int

	for {
		idCount++
		id := idCount

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
			spec = []interface{}{
				"return",
				[]interface{}{"i32.const", "-1"},
			}
		}

		testFunc = append(testFunc, []interface{}{
			"if",
			[]interface{}{
				"i32.eq",
				[]interface{}{"get_local", "$arg"},
				[]interface{}{"i32.const", strconv.Itoa(0x100000 + id)},
			},
			[]interface{}{spec},
		})

		if test != nil {
			testFunc = append(testFunc, []interface{}{
				"if",
				[]interface{}{
					"i32.eq",
					[]interface{}{"get_local", "$arg"},
					[]interface{}{"i32.const", strconv.Itoa(id)},
				},
				[]interface{}{test},
			})
		}
	}

	testFunc = append(testFunc, []interface{}{"unreachable"})

	module = append(module, testFunc)

	module = append(module, []interface{}{
		"start",
		"$test",
	})

	m := loadModule(module)
	text, roData, data, bssSize := m.Code()

	if writeBin {
		textName := path.Join("testdata", strings.Replace(path.Base(filename), ".wast", "-text.bin", -1))

		f, err := os.Create(textName)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := f.Write(text); err != nil {
			t.Fatal(err)
		}

		f.Close()

		roDataName := path.Join("testdata", strings.Replace(path.Base(filename), ".wast", "-rodata.bin", -1))

		f, err = os.Create(roDataName)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := f.Write(roData); err != nil {
			t.Fatal(err)
		}

		f.Close()

		if dumpText {
			dump := exec.Command("objdump", "-D", "-bbinary", "-mi386:x86-64", textName)
			dump.Stdout = os.Stdout
			dump.Stderr = os.Stderr

			if err := dump.Run(); err != nil {
				t.Fatal(err)
			}
		}

		if dumpROData {
			dump := exec.Command("hexdump", roDataName)
			dump.Stdout = os.Stdout
			dump.Stderr = os.Stderr

			if err := dump.Run(); err != nil {
				t.Fatal(err)
			}
		}
	}

	var timedout bool

	p, err := runner.NewProgram(text, roData, data, bssSize)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if !timedout {
			p.Close()
		}
	}()

	r, err := p.NewRunner(stackSize)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if !timedout {
			r.Close()
		}
	}()

	for id := 1; id != idCount; id++ {
		assertType, err := r.Run(0x100000 + id)
		if err != nil {
			t.Fatal(err)
		}
		if assertType < -1 || assertType > 1 {
			panic(assertType)
		}

		if assertType == -1 {
			t.Logf("run: test #%d: not supported", id)
			continue
		}

		var result int32
		var panicked interface{}
		done := make(chan struct{})

		go func() {
			defer close(done)
			defer func() {
				panicked = recover()
			}()
			result, err = r.Run(id)
		}()

		timer := time.NewTimer(timeout)

		select {
		case <-done:
			timer.Stop()

		case <-timer.C:
			timedout = true
			t.Fatalf("run: test #%d: timeout", id)
		}

		if panicked != nil {
			t.Fatalf("run: test #%d: panic: %v", id, panicked)
		}

		if err != nil {
			if _, ok := err.(traps.Id); ok {
				if assertType == 1 {
					t.Logf("run: test #%d: trap ok", id)
				} else {
					t.Errorf("run: test #%d: failed due to unexpected trap", id)
				}
			} else {
				t.Fatal(err)
			}
		} else {
			if assertType == 0 {
				switch result {
				case 1:
					t.Logf("run: test #%d: return ok", id)

				case 0:
					t.Errorf("run: test #%d: return fail", id)

				default:
					t.Fatalf("run: test #%d: bad result: %d", id, result)
				}
			} else {
				t.Fatalf("run: test #%d: failed due to unexpected return (result: %d)", id, result)
			}
		}
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
