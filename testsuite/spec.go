// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"

	"gate.computer/gate/image"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
)

//go:generate python3 spec_test.py

func generateSpecData() error {
	python := os.Getenv("PYTHON")
	if python == "" {
		python = "python3"
	}

	cmd := exec.Command(python, "specdata.py")
	cmd.Stderr = os.Stderr
	cmd.Dir = "testdata"
	return cmd.Run()
}

type specInstance struct {
	prog  *program
	image *image.Instance
}

func instantiateSpec(t *testing.T, filename string, expect *expected) *specInstance {
	cleanup := false

	prog := buildProgram(t, filename, readSpecData(t, filename), expect)
	if prog == nil {
		return nil
	}
	defer func() {
		if !cleanup {
			prog.close(t)
		}
	}()

	inst := newInstance(t, prog, "")
	if inst == nil {
		return nil
	}
	defer func() {
		if !cleanup {
			inst.Close()
		}
	}()

	out := bytes.NewBuffer(nil)
	res, trapID := run(t, prog.image, inst, specService(out))
	if out.Len() > 0 {
		t.Logf("output:%s", out)
	}

	if trapID != trap.Exit {
		t.Fatal(trapID)
		return nil
	}
	if res != 0 {
		t.Log("instantiation result is not zero")
	}

	if err := inst.CheckMutation(); err != nil {
		t.Fatal(err)
		return nil
	}

	cleanup = true
	return &specInstance{prog, inst}
}

func (s *specInstance) close(t *testing.T) {
	if s == nil {
		return
	}

	defer s.prog.close(t)
	if err := s.image.Close(); err != nil {
		t.Error(err)
	}
}

func (s *specInstance) invoke(t *testing.T, field string, args []arg, restype *wa.Type) (uint64, trap.ID) {
	index, sig, found := s.prog.mod.ExportFunc(field)
	if !found {
		t.Fatal("field not found")
	}
	if restype != nil && *restype != sig.Result {
		t.Fatal(*restype, sig.Result)
	}
	if len(args) != len(sig.Params) {
		t.Fatal(len(args), len(sig.Params))
	}
	values := make([]uint64, len(args))
	for i, arg := range args {
		if arg.Type != sig.Params[i] {
			t.Fatal(i, arg.Type, sig.Params[i])
		}
		values[i] = arg.Value
	}
	if err := s.image.ReplaceCallStack(s.prog.funcs.FuncAddrs[index], values); err != nil {
		t.Fatal(err)
	}

	out := bytes.NewBuffer(nil)
	_, trapID := run(t, s.prog.image, s.image, specService(out))
	if out.Len() > 0 {
		t.Logf("output:%s", out)
	}

	if restype == nil {
		if err := s.image.CheckMutation(); err != nil {
			t.Fatal(err)
		}
		return 0, trapID
	}

	ret, err := s.image.CheckHaltedMutation(restype.Category())
	if err != nil {
		t.Fatal(err)
	}
	return ret, trapID
}

const (
	opNop = iota
	opPrintI32
	opPrintI64
	opPrintF32
	opPrintF64
)

func specService(b *bytes.Buffer) func([]byte) []byte {
	return func(p []byte) []byte {
		ops := p[:8]
		args := p[8:]

		for _, op := range ops {
			if op == opNop {
				continue
			}

			fmt.Fprint(b, " ")

			switch op {
			case opPrintI32:
				fmt.Fprint(b, binary.LittleEndian.Uint32(args))
				args = args[4:]

			case opPrintI64:
				fmt.Fprint(b, binary.LittleEndian.Uint64(args))
				args = args[8:]

			case opPrintF32:
				fmt.Fprint(b, math.Float32frombits(binary.LittleEndian.Uint32(args)))
				args = args[4:]

			case opPrintF64:
				fmt.Fprint(b, math.Float64frombits(binary.LittleEndian.Uint64(args)))
				args = args[8:]

			default:
				fmt.Fprintf(b, "<invalid op %d>", op)
				return nil
			}
		}

		return nil
	}
}

type specTestInstance struct {
	spec *specInstance
	name string
	link bool
}

func instantiateSpecTest(t *testing.T, name, filename string) *specTestInstance {
	t.Log("module:", name)

	expect := &expected{
		moduleError: isUnsupported,
		codeError:   isUnsupported,
		dataError:   isUnsupported,
		customError: isUnsupported,
	}

	s := instantiateSpec(t, filename, expect)
	if s == nil {
		return &specTestInstance{name: name}
	}

	return &specTestInstance{
		spec: s,
		name: name,
	}
}

func (x *specTestInstance) close(t *testing.T) {
	if x.spec == nil {
		return
	}

	defer x.spec.prog.close(t)
	if err := x.spec.image.Close(); err != nil {
		t.Error(err)
	}
}

func (x *specTestInstance) unsupported() bool {
	return x.spec == nil
}

func (x *specTestInstance) prologue(t *testing.T, field string) {
	t.Helper()
	if x.unsupported() {
		t.Skipf("referenced module %s uses unsupported extensions", x.name)
	}
	t.Log("module:", x.name)
	t.Logf("field: %q", field)
}

func (x *specTestInstance) register(t *testing.T) {
	t.Log("register:", x.name)
	x.link = true
}

func (x *specTestInstance) invoke(t *testing.T, field string, args []arg) {
	x.prologue(t, field)
	t.Log("args:", args)

	if _, trapID := x.spec.invoke(t, field, args, nil); trapID != trap.Exit {
		t.Fatal(trapID)
	}
}

func (x *specTestInstance) assertExhaustion(t *testing.T, field string, args []arg, expect arg, text string) {
	x.prologue(t, field)
	t.Log("args:", args)

	if _, trapID := x.spec.invoke(t, field, args, nil); trapID != trap.CallStackExhausted {
		t.Fatal("not exhausted")
	}
}

func (x *specTestInstance) assertReturnInvoke(t *testing.T, field string, args []arg, expect arg) {
	if x.link && strings.HasPrefix(t.Name(), "Test_elem/call-") {
		t.Skip("linking not supported")
	}

	x.prologue(t, field)
	t.Log("args:", args)
	t.Log("expect:", expect)

	value, trapID := x.spec.invoke(t, field, args, &expect.Type)
	if trapID != trap.Exit {
		t.Fatal(trapID)
	}

	if r := (arg{expect.Type, value}); !r.equal(t, expect) {
		t.Fatal("result:", r)
	}
}

func (x *specTestInstance) assertReturnGet(t *testing.T, field string, expect arg) {
	x.prologue(t, field)
	t.Log("expect:", expect)

	if !(strings.HasPrefix(t.Name(), "Test_exports/") && x.name == "$Global" && field == "e") {
		t.Fatal("access to global values not implemented")
	}

	b := x.spec.prog.globals
	if len(b) == 0 {
		t.Fatal("no globals")
	}
	value := binary.LittleEndian.Uint64(b[len(b)-obj.Word:])

	if g := (arg{expect.Type, value}); !g.equal(t, expect) {
		t.Error("global:", g)
	}
}

func (x *specTestInstance) assertTrap(t *testing.T, field string, args []arg, expect arg, text string) {
	x.prologue(t, field)
	t.Log("args:", args)
	t.Log("expect:", text)

	_, trapID := x.spec.invoke(t, field, args, &expect.Type)

	switch {
	case text == "integer divide by zero" && trapID == trap.IntegerDivideByZero:
	case text == "integer overflow" && trapID == trap.IntegerOverflow:
	case text == "invalid conversion to integer" && trapID == trap.IntegerOverflow:
	case text == "out of bounds memory access" && trapID == trap.MemoryAccessOutOfBounds:
	case text == "undefined element" && trapID == trap.IndirectCallIndexOutOfBounds:
	case text == "unreachable" && trapID == trap.Unreachable:

	default:
		t.Fatal(trapID)
	}
}

func assertInvalidSpec(t *testing.T, filename, text string) {
	t.Log("expect:", text)

	expect := &expected{
		moduleError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "constant expression required":
				switch {
				case strings.HasPrefix(msg, "unexpected operation in initializer expression when expecting end"):
					return true
				case strings.HasPrefix(msg, "unsupported operation in initializer expression"):
					return true
				}

			case "duplicate export name":
				switch {
				case strings.HasPrefix(msg, "duplicate export name"):
					return true
				}

			case "memory size must be at most 65536 pages (4GiB)":
				switch {
				case strings.HasPrefix(msg, "invalid initial memory size"):
					return true
				case strings.HasPrefix(msg, "invalid maximum memory size"):
					return true
				}

			case "multiple memories":
				switch {
				case msg == "multiple memories not supported":
					return true
				}

			case "size minimum must not be greater than maximum":
				switch {
				case msg == "maximum memory size 0 is smaller than initial memory size 1":
					return true
				case msg == "maximum table size 0 is smaller than initial table size 1":
					return true
				case strings.HasPrefix(msg, "initial table size is too large"):
					return true
				}

			case "start function":
				switch {
				case strings.HasPrefix(msg, "invalid start function signature"):
					return true
				}

			case "type mismatch":
				switch {
				case strings.HasPrefix(msg, "custom section id"):
					return true
				case strings.HasPrefix(msg, "offset initializer expression has invalid type"):
					return true
				case strings.HasPrefix(msg, "unexpected operation in initializer expression when expecting end"):
					return true
				case strings.HasPrefix(msg, "unsupported operation in initializer expression"):
					return true
				case strings.HasPrefix(msg, "unsupported table index"):
					return true
				case strings.Contains(msg, "initializer expression has wrong type"):
					return true
				}

			case "unknown data segment", "unknown data segment 1":
				switch {
				case strings.HasPrefix(msg, "custom section id"):
					return true
				case strings.Contains(msg, "initializer expression has wrong type"):
					return true
				}

			case "unknown function":
				switch {
				case strings.HasPrefix(msg, "export function index out of bounds"):
					return true
				case strings.HasPrefix(msg, "table element index out of bounds"):
					return true
				case strings.HasPrefix(msg, "start function index out of bounds"):
					return true
				}

			case "unknown global":
				switch {
				case strings.HasPrefix(msg, "get_global index out of bounds"):
					return true
				case strings.HasPrefix(msg, "import global index out of bounds in initializer expression"):
					return true
				}

			case "unknown global 0", "unknown global 1":
				switch {
				case strings.HasPrefix(msg, "import global index out of bounds in initializer expression"):
					return true
				}

			case "unknown table":
				switch {
				case strings.HasSuffix(msg, "exceeds initial table size"):
					return true
				}

			case "unknown type":
				switch {
				case strings.HasPrefix(msg, "function type index out of bounds"):
					return true
				}
			}

			return false
		},

		codeError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "global is immutable":
				switch {
				case msg == "set_global: global 0 is immutable":
					return true
				}

			case "invalid result arity":
				switch {
				case msg == "block has no operand to pop":
					return true
				}

			case "type mismatch":
				switch {
				case msg == "block has no operand to drop":
					return true
				case msg == "block has no operand to pop":
					return true
				case msg == "function call parameter count exceeds stack operand count":
					return true
				case msg == "if without else has result type":
					return true
				case msg == "operand stack not empty at end of function":
					return true
				case msg == "unknown block type 1":
					return true
				case strings.HasPrefix(msg, "br_table targets have inconsistent value types"):
					return true
				case strings.HasPrefix(msg, "select: operands have inconsistent types"):
					return true
				case strings.Contains(msg, "has wrong type"):
					return true
				case strings.Contains(msg, "operands have wrong types"):
					return true
				}

			case "unknown function":
				switch {
				case strings.Contains(msg, "function index out of bounds"):
					return true
				}

			case "unknown global":
				switch {
				case strings.Contains(msg, "global index out of bounds"):
					return true
				}

			case "unknown label":
				switch {
				case strings.HasPrefix(msg, "relative branch depth out of bounds"):
					return true
				}

			case "unknown local":
				switch {
				case strings.Contains(msg, "local index out of bounds"):
					return true
				}

			case "unknown type":
				switch {
				case strings.Contains(msg, "signature index out of bounds"):
					return true
				}
			}

			return false
		},

		dataError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "constant expression required":
				switch {
				case strings.HasPrefix(msg, "unexpected operation in initializer expression when expecting end"):
					return true
				case strings.HasPrefix(msg, "unsupported operation in initializer expression"):
					return true
				}

			case "type mismatch":
				switch {
				case strings.HasPrefix(msg, "offset initializer expression has invalid type"):
					return true
				case strings.HasPrefix(msg, "unexpected operation in initializer expression when expecting end"):
					return true
				case strings.HasPrefix(msg, "unsupported operation in initializer expression"):
					return true
				}

			case "unknown global 0", "unknown global 1":
				switch {
				case strings.HasPrefix(msg, "import global index out of bounds in initializer expression"):
					return true
				}

			case "unknown memory":
				switch {
				case strings.HasSuffix(msg, "exceeds initial memory size"):
					return true
				}

			case "unknown memory 1":
				switch {
				case strings.HasPrefix(msg, "unsupported memory index"):
					return true
				}
			}

			return false
		},
	}

	p := buildProgram(t, filename, readSpecData(t, filename), expect)
	if p == nil {
		return
	}
	defer p.close(t)

	t.Fatal("invalidity not detected")
}

func assertMalformedSpec(t *testing.T, filename, text string) {
	t.Log("expect:", text)

	expect := &expected{
		moduleError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "data count and data section have inconsistent lengths":
				switch {
				case strings.HasPrefix(msg, "custom section id"):
					return true
				}

			case "integer representation too long":
				switch {
				case strings.Contains(msg, "encoding is too"):
					return true
				case strings.Contains(msg, "value is too"):
					return true
				}

			case "integer too large":
				switch {
				case strings.Contains(msg, "value is too"):
					return true
				}

			case "length out of bounds":
				switch {
				case msg == "unexpected EOF":
					return true
				}

			case "magic header not detected":
				switch {
				case msg == "not a WebAssembly module":
					return true
				case msg == "unexpected EOF":
					return true
				}

			case "malformed import kind":
				switch {
				case strings.HasPrefix(msg, "import kind not supported"):
					return true
				}

			case "malformed mutability":
				switch {
				case msg == "varuint1 value is too large":
					return true
				}

			case "malformed section id":
				switch {
				case strings.HasPrefix(msg, "custom section id"):
					return true
				}

			case "malformed UTF-8 encoding":
				switch {
				case strings.HasSuffix(msg, "name is not a valid UTF-8 string"):
					return true
				}

			case "section size mismatch":
				switch {
				case msg == "unexpected EOF":
					return true
				case strings.HasPrefix(msg, "custom section id"):
					return true
				case strings.HasPrefix(msg, "start function index out of bounds"):
					return true
				case strings.Contains(msg, "follows section"):
					return true
				}

			case "unexpected content after last section":
				switch {
				case strings.Contains(msg, "follows section"):
					return true
				}

			case "unexpected end", "unexpected end of section or function":
				switch {
				case msg == "unexpected EOF":
					return true
				}

			case "unknown binary version":
				switch {
				case strings.HasPrefix(msg, "unsupported module version"):
					return true
				}
			}

			return false
		},

		codeError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "function and code section have inconsistent lengths":
				switch {
				case strings.HasPrefix(msg, "wrong number of function bodies"):
					return true
				}

			case "integer representation too long":
				switch {
				case strings.Contains(msg, "encoding is too"):
					return true
				}

			case "integer too large":
				switch {
				case strings.Contains(msg, "value is too"):
					return true
				}

			case "too many locals":
				switch {
				case strings.Contains(msg, "has too many variables"):
					return true
				}

			case "unexpected end":
				switch {
				case msg == "unexpected EOF":
					return true
				}

			case "zero byte expected":
				switch {
				case strings.HasSuffix(msg, "reserved byte is not zero"):
					return true
				}
			}

			return false
		},

		dataError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "integer representation too long":
				switch {
				case strings.Contains(msg, "encoding is too"):
					return true
				}

			case "integer too large":
				switch {
				case strings.Contains(msg, "value is too"):
					return true
				}

			case "unexpected end of section or function":
				switch {
				case msg == "unexpected EOF":
					return true
				}
			}

			return false
		},

		customError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "section size mismatch":
				switch {
				case msg == "unexpected EOF":
					return true
				}
			}

			return false
		},
	}

	p := buildProgram(t, filename, readSpecData(t, filename), expect)
	if p == nil {
		return
	}
	defer p.close(t)

	t.Fatal("malformation not detected")
}

func assertUninstantiableSpec(t *testing.T, filename, text string) {
	t.Log("expect:", text)

	expect := &expected{
		moduleError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "out of bounds table access":
				switch {
				case strings.Contains(msg, "exceeds initial table size"):
					return true
				}
			}

			return false
		},

		codeError: func(err error) bool {
			skipUnsupported(t, err)
			return false
		},

		dataError: func(err error) bool {
			msg := skipUnsupported(t, err)

			switch text {
			case "out of bounds memory access":
				switch {
				case strings.Contains(msg, "exceeds initial memory size"):
					return true
				}

			case "unknown memory 0", "unknown memory 1":
				switch {
				case strings.HasPrefix(text, "unsupported memory index"):
					return true
				}
			}

			return false
		},

		customError: func(err error) bool {
			skipUnsupported(t, err)
			return false
		},
	}

	prog := buildProgram(t, filename, readSpecData(t, filename), expect)
	if prog == nil {
		return
	}
	defer prog.close(t)

	inst := newInstance(t, prog, "")
	if inst == nil {
		return
	}
	defer inst.Close()

	_, trapID := run(t, prog.image, inst, nil)

	switch {
	case text == "unreachable" && trapID == trap.Unreachable:
		return
	}

	t.Fatal(trapID)
}

func isUnsupported(err error) bool {
	msg := err.Error()

	switch {
	case msg == "import kind not supported: memory":
		return true
	case msg == "import kind not supported: table":
		return true
	case msg == "invalid opcode: 0xc0":
		return true
	case msg == "invalid opcode: 0xc1":
		return true
	case msg == "invalid opcode: 0xc2":
		return true
	case msg == "invalid opcode: 0xc3":
		return true
	case msg == "invalid opcode: 0xc4":
		return true
	case msg == "invalid opcode: 0xd1":
		return true
	case msg == "invalid opcode: 0xfc":
		return true
	case msg == "multiple return values not supported":
		return true
	case msg == "multiple tables not supported":
		return true
	case msg == "unknown value type -16":
		return true
	case msg == "unknown value type -17":
		return true
	case msg == "unsupported table element type: -17":
		return true
	case strings.HasPrefix(msg, "custom section id"):
		return true
	case strings.HasPrefix(msg, "unsupported memory index"):
		return true
	case strings.HasPrefix(msg, "unsupported mutable global in import"):
		return true
	case strings.HasPrefix(msg, "unsupported table index"):
		return true
	}

	return false
}

func skipUnsupported(t *testing.T, err error) string {
	t.Helper()
	if isUnsupported(err) {
		t.Skip(err)
	}
	return err.Error()
}

func readSpecData(t *testing.T, filename string) []byte {
	return readTestData(t, path.Join("specdata", filename))
}
