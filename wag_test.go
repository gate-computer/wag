package wag

import (
	"fmt"
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
	parallel   = false
	writeBin   = true
	dumpText   = true
	dumpROData = true
	dumpData   = true

	maxRODataSize = 0x100000
	memorySize    = 0x100000
	stackSize     = 0x100000

	timeout = time.Hour // time.Second * 3
)

type fun func() int32

type startFunc struct {
	f *fun
}

type startFuncPtr *startFunc

//func TestLoop(t *testing.T) { test(t, "testdata/spec/ml-proto/test/loop.wast") }

func TestBlock(t *testing.T)            { test(t, "testdata/spec/ml-proto/test/block.wast") }
func TestBrIf(t *testing.T)             { test(t, "testdata/spec/ml-proto/test/br_if.wast") }
func TestBranchStackDelta(t *testing.T) { test(t, "testdata/branch_stack_delta.wast") }
func TestFac(t *testing.T)              { test(t, "testdata/spec/ml-proto/test/fac.wast") }
func TestForward(t *testing.T)          { test(t, "testdata/spec/ml-proto/test/forward.wast") }
func TestFunc(t *testing.T)             { test(t, "testdata/spec/ml-proto/test/func.wast") }
func TestI32(t *testing.T)              { test(t, "testdata/i32.wast") }
func TestI64(t *testing.T)              { test(t, "testdata/i64.wast") }
func TestIntLiterals(t *testing.T)      { test(t, "testdata/spec/ml-proto/test/int_literals.wast") }
func TestLabels(t *testing.T)           { test(t, "testdata/spec/ml-proto/test/labels.wast") }
func TestLotsOfLocals(t *testing.T)     { test(t, "testdata/lots_of_locals.wast") }
func TestMemory(t *testing.T)           { test(t, "testdata/spec/ml-proto/test/memory.wast") }
func TestNop(t *testing.T)              { test(t, "testdata/spec/ml-proto/test/nop.wast") }
func TestTypecheck(t *testing.T)        { test(t, "testdata/spec/ml-proto/test/typecheck.wast") }

func test(t *testing.T, filename string) {
	if parallel {
		t.Parallel()
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	name := strings.Replace(path.Base(filename), ".wast", "", -1)

	for i := 0; len(data) > 0; i++ {
		data = testModule(t, data, fmt.Sprintf("%s-%d", name, i))
	}
}

func testModule(t *testing.T, data []byte, filename string) []byte {
	module, data := sexp.ParsePanic(data)
	if module == nil {
		return nil
	}

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

		assert, tail := sexp.ParsePanic(data)
		if assert == nil {
			data = tail
			break
		}

		assertName := assert[0].(string)
		if assertName == "module" {
			break
		}

		data = tail

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

	{
		var timedout bool

		m := loadModule(module)

		b, err := runner.NewBuffer(maxRODataSize)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if !timedout {
				b.Close()
			}
		}()

		text, roData, globals, data := m.Code(b.RODataAddr(), b.ROData)

		b.Seal()

		if writeBin {
			textName := path.Join("testdata", filename+"-text.bin")

			f, err := os.Create(textName)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := f.Write(text); err != nil {
				t.Fatal(err)
			}

			f.Close()

			roDataName := path.Join("testdata", filename+"-rodata.bin")

			f, err = os.Create(roDataName)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := f.Write(roData); err != nil {
				t.Fatal(err)
			}

			f.Close()

			dataName := path.Join("testdata", filename+"-data.bin")

			f, err = os.Create(dataName)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := f.Write(data); err != nil {
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
				fmt.Println(roDataName + ":")

				dump := exec.Command("hexdump", "-C", roDataName)
				dump.Stdout = os.Stdout
				dump.Stderr = os.Stderr

				if err := dump.Run(); err != nil {
					t.Fatal(err)
				}
			}

			if dumpData {
				fmt.Println(dataName + ":")

				dump := exec.Command("hexdump", "-C", dataName)
				dump.Stdout = os.Stdout
				dump.Stderr = os.Stderr

				if err := dump.Run(); err != nil {
					t.Fatal(err)
				}
			}
		}

		p, err := b.NewProgram(text, data, globals)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if !timedout {
				p.Close()
			}
		}()

		r, err := p.NewRunner(memorySize, stackSize)
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
				t.Logf("run: module %s: test #%d: not supported", filename, id)
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
				t.Fatalf("run: module %s: test #%d: timeout", filename, id)
			}

			if panicked != nil {
				t.Fatalf("run: module %s: test #%d: panic: %v", filename, id, panicked)
			}

			if err != nil {
				if _, ok := err.(traps.Id); ok {
					if assertType == 1 {
						t.Logf("run: module %s: test #%d: trap ok", filename, id)
					} else {
						t.Errorf("run: module %s: test #%d: failed due to unexpected trap", filename, id)
					}
				} else {
					t.Fatal(err)
				}
			} else {
				if assertType == 0 {
					switch result {
					case 1:
						t.Logf("run: module %s: test #%d: return ok", filename, id)

					case 0:
						t.Errorf("run: module %s: test #%d: return fail", filename, id)

					default:
						t.Fatalf("run: module %s: test #%d: bad result: %d", filename, id, result)
					}
				} else {
					t.Fatalf("run: module %s: test #%d: failed due to unexpected return (result: %d)", filename, id, result)
				}
			}
		}
	}

	return data
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
