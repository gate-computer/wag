package wag

import (
	"bytes"
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
	parallel    = false
	writeBin    = true
	dumpText    = false
	dumpROData  = false
	dumpData    = false
	dumpFuncMap = false
	dumpCallMap = false

	maxRODataSize = 0x100000
	maxMemorySize = 0x100000
	stackSize     = 0x1000 // limit stacktrace length

	timeout = time.Second * 3
)

// for i in $(ls -1 *.wast); do echo 'func Test_'$(echo $i | sed 's/.wast$//' | tr - _ | tr . _)'(t *testing.T) { test(t, "'$(echo $i | sed 's/.wast$//')'") }'; done

// func Test_binary(t *testing.T)                        { test(t, "binary") }
// func Test_br_table(t *testing.T)                      { test(t, "br_table") }
// func Test_call(t *testing.T)                          { test(t, "call") }
// func Test_call_indirect(t *testing.T)                 { test(t, "call_indirect") }
// func Test_comments(t *testing.T)                      { test(t, "comments") }
// func Test_conversions(t *testing.T)                   { test(t, "conversions") }
// func Test_endianness(t *testing.T)                    { test(t, "endianness") }
// func Test_f32(t *testing.T)                           { test(t, "f32") }
// func Test_f32_cmp(t *testing.T)                       { test(t, "f32_cmp") }
// func Test_f64(t *testing.T)                           { test(t, "f64") }
// func Test_f64_cmp(t *testing.T)                       { test(t, "f64_cmp") }
// func Test_float_exprs(t *testing.T)                   { test(t, "float_exprs") }
// func Test_float_literals(t *testing.T)                { test(t, "float_literals") }
// func Test_float_memory(t *testing.T)                  { test(t, "float_memory") }
// func Test_float_misc(t *testing.T)                    { test(t, "float_misc") }
// func Test_func_local_before_param_fail(t *testing.T)  { test(t, "func-local-before-param.fail") }
// func Test_func_local_before_result_fail(t *testing.T) { test(t, "func-local-before-result.fail") }
// func Test_func_ptrs(t *testing.T)                     { test(t, "func_ptrs") }
// func Test_func_result_before_param_fail(t *testing.T) { test(t, "func-result-before-param.fail") }
// func Test_get_local(t *testing.T)                     { test(t, "get_local") }
// func Test_if_label_scope_fail(t *testing.T)           { test(t, "if_label_scope.fail") }
// func Test_left_to_right(t *testing.T)                 { test(t, "left-to-right") }
// func Test_loop(t *testing.T)                          { test(t, "loop") }
// func Test_memory_redundancy(t *testing.T)             { test(t, "memory_redundancy") }
// func Test_names(t *testing.T)                         { test(t, "names") }
// func Test_return(t *testing.T)                        { test(t, "return") }
// func Test_set_local(t *testing.T)                     { test(t, "set_local") }
// func Test_start(t *testing.T)                         { test(t, "start") }
// func Test_store_retval(t *testing.T)                  { test(t, "store_retval") }
// func Test_switch(t *testing.T)                        { test(t, "switch") }
// func Test_traps(t *testing.T)                         { test(t, "traps") }

func Test_address(t *testing.T)                         { test(t, "address") }
func Test_block(t *testing.T)                           { test(t, "block") }
func Test_br(t *testing.T)                              { test(t, "br") }
func Test_br_if(t *testing.T)                           { test(t, "br_if") }
func Test_break_drop(t *testing.T)                      { test(t, "break-drop") }
func Test_exports(t *testing.T)                         { test(t, "exports") }
func Test_f32_load32_fail(t *testing.T)                 { test(t, "f32.load32.fail") }
func Test_f32_load64_fail(t *testing.T)                 { test(t, "f32.load64.fail") }
func Test_f32_store32_fail(t *testing.T)                { test(t, "f32.store32.fail") }
func Test_f32_store64_fail(t *testing.T)                { test(t, "f32.store64.fail") }
func Test_f64_load32_fail(t *testing.T)                 { test(t, "f64.load32.fail") }
func Test_f64_load64_fail(t *testing.T)                 { test(t, "f64.load64.fail") }
func Test_f64_store32_fail(t *testing.T)                { test(t, "f64.store32.fail") }
func Test_f64_store64_fail(t *testing.T)                { test(t, "f64.store64.fail") }
func Test_fac(t *testing.T)                             { test(t, "fac") }
func Test_forward(t *testing.T)                         { test(t, "forward") }
func Test_func(t *testing.T)                            { test(t, "func") }
func Test_func_local_after_body_fail(t *testing.T)      { test(t, "func-local-after-body.fail") }
func Test_func_param_after_body_fail(t *testing.T)      { test(t, "func-param-after-body.fail") }
func Test_func_result_after_body_fail(t *testing.T)     { test(t, "func-result-after-body.fail") }
func Test_i32(t *testing.T)                             { test(t, "i32") }
func Test_i32_load32_s_fail(t *testing.T)               { test(t, "i32.load32_s.fail") }
func Test_i32_load32_u_fail(t *testing.T)               { test(t, "i32.load32_u.fail") }
func Test_i32_load64_s_fail(t *testing.T)               { test(t, "i32.load64_s.fail") }
func Test_i32_load64_u_fail(t *testing.T)               { test(t, "i32.load64_u.fail") }
func Test_i32_store32_fail(t *testing.T)                { test(t, "i32.store32.fail") }
func Test_i32_store64_fail(t *testing.T)                { test(t, "i32.store64.fail") }
func Test_i64(t *testing.T)                             { test(t, "i64") }
func Test_i64_load64_s_fail(t *testing.T)               { test(t, "i64.load64_s.fail") }
func Test_i64_load64_u_fail(t *testing.T)               { test(t, "i64.load64_u.fail") }
func Test_i64_store64_fail(t *testing.T)                { test(t, "i64.store64.fail") }
func Test_imports(t *testing.T)                         { test(t, "imports") }
func Test_int_exprs(t *testing.T)                       { test(t, "int_exprs") }
func Test_int_literals(t *testing.T)                    { test(t, "int_literals") }
func Test_labels(t *testing.T)                          { test(t, "labels") }
func Test_memory(t *testing.T)                          { test(t, "memory") }
func Test_memory_trap(t *testing.T)                     { test(t, "memory_trap") }
func Test_nop(t *testing.T)                             { test(t, "nop") }
func Test_of_string_overflow_hex_u32_fail(t *testing.T) { test(t, "of_string-overflow-hex-u32.fail") }
func Test_of_string_overflow_hex_u64_fail(t *testing.T) { test(t, "of_string-overflow-hex-u64.fail") }
func Test_of_string_overflow_s32_fail(t *testing.T)     { test(t, "of_string-overflow-s32.fail") }
func Test_of_string_overflow_s64_fail(t *testing.T)     { test(t, "of_string-overflow-s64.fail") }
func Test_of_string_overflow_u32_fail(t *testing.T)     { test(t, "of_string-overflow-u32.fail") }
func Test_of_string_overflow_u64_fail(t *testing.T)     { test(t, "of_string-overflow-u64.fail") }
func Test_resizing(t *testing.T)                        { test(t, "resizing") }
func Test_select(t *testing.T)                          { test(t, "select") }
func Test_typecheck(t *testing.T)                       { test(t, "typecheck") }
func Test_unreachable(t *testing.T)                     { test(t, "unreachable") }

func test(t *testing.T, name string) {
	if parallel {
		t.Parallel()
	}

	filename := path.Join("testdata/spec/ml-proto/test", name) + ".wast"

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	if strings.HasSuffix(name, ".fail") {
		defer func() {
			x := recover()
			if x == nil {
				t.Error()
			} else {
				t.Logf("expected panic: %s", x)
			}
		}()
	}

	for i := 1; len(data) > 0; i++ {
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
				var check interface{}

				switch exprType {
				case "f32", "f64":
					bitsType := strings.Replace(exprType, "f", "i", 1)

					check = []interface{}{
						bitsType + ".eq",
						[]interface{}{
							bitsType + ".reinterpret/" + exprType,
							assert[1],
						},
						[]interface{}{
							bitsType + ".reinterpret/" + exprType,
							assert[2],
						},
					}

				default:
					check = []interface{}{exprType + ".eq", assert[1], assert[2]}
				}

				test = []interface{}{"return", check}
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

		text, roData, globals, data, funcMap, callMap := m.Code(b.Imports, b.RODataAddr(), b.ROData)

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

			funcMapName := path.Join("testdata", filename+"-funcmap.bin")

			f, err = os.Create(funcMapName)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := f.Write(funcMap); err != nil {
				t.Fatal(err)
			}

			f.Close()

			callMapName := path.Join("testdata", filename+"-callmap.bin")

			f, err = os.Create(callMapName)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := f.Write(callMap); err != nil {
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

			if dumpFuncMap {
				fmt.Println(funcMapName + ":")

				dump := exec.Command("hexdump", "-C", funcMapName)
				dump.Stdout = os.Stdout
				dump.Stderr = os.Stderr

				if err := dump.Run(); err != nil {
					t.Fatal(err)
				}
			}

			if dumpCallMap {
				fmt.Println(callMapName + ":")

				dump := exec.Command("hexdump", "-C", callMapName)
				dump.Stdout = os.Stdout
				dump.Stderr = os.Stderr

				if err := dump.Run(); err != nil {
					t.Fatal(err)
				}
			}
		}

		p, err := b.NewProgram(text, globals, data, funcMap, callMap, m.FuncTypes(), m.FuncNames())
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if !timedout {
				p.Close()
			}
		}()

		memGrowSize := maxMemorySize
		if m.Memory.MaxSize > 0 && memGrowSize > m.Memory.MaxSize {
			memGrowSize = m.Memory.MaxSize
		}

		r, err := p.NewRunner(m.Memory.MinSize, memGrowSize, stackSize)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if !timedout {
				r.Close()
			}
		}()

		importSigs := m.ImportTypes()

		for id := 1; id != idCount; id++ {
			var printBuf bytes.Buffer
			printBuf.WriteByte(10)

			assertType, err := r.Run(0x100000+id, importSigs, &printBuf)
			if printBuf.Len() > 1 {
				t.Logf("run: module %s: print: %s", filename, string(printBuf.Bytes()))
			}
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
				result, err = r.Run(id, importSigs, &printBuf)
			}()

			timer := time.NewTimer(timeout)

			select {
			case <-done:
				timer.Stop()

			case <-timer.C:
				timedout = true
				t.Fatalf("run: module %s: test #%d: timeout", filename, id)
			}

			if printBuf.Len() > 1 {
				t.Logf("run: module %s: test #%d: printed: %s", filename, id, string(printBuf.Bytes()))
			}

			if panicked != nil {
				t.Fatalf("run: module %s: test #%d: panic: %v", filename, id, panicked)
			}

			var stackBuf bytes.Buffer
			stackBuf.WriteByte(10)
			if err := r.WriteStacktraceTo(&stackBuf); err == nil {
				if stackBuf.Len() > 1 {
					t.Logf("run: module %s: test #%d: stack: %s", filename, id, string(stackBuf.Bytes()))
				}
			} else {
				t.Errorf("run: module %s: test #%d: stack error: %v", filename, id, err)
			}

			if err != nil {
				if _, ok := err.(traps.Id); ok {
					if assertType == 1 {
						t.Logf("run: module %s: test #%d: pass", filename, id)
					} else {
						t.Errorf("run: module %s: test #%d: FAIL due to unexpected trap", filename, id)
					}
				} else {
					t.Fatal(err)
				}
			} else {
				if assertType == 0 {
					switch result {
					case 1:
						t.Logf("run: module %s: test #%d: pass", filename, id)

					case 0:
						t.Errorf("run: module %s: test #%d: FAIL", filename, id)

					default:
						t.Fatalf("run: module %s: test #%d: bad result: %d", filename, id, result)
					}
				} else {
					t.Errorf("run: module %s: test #%d: FAIL due to unexpected return (result: %d)", filename, id, result)
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
