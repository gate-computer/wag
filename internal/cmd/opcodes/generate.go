// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var re = regexp.MustCompile("\n\\| +`([^`]+)` +\\| +`(0x[0-9a-f]{2})` +\\| +([a-z_]+ +: +)?`?([^ `|]*)`?[ |]")

type opcode struct {
	name, sym, imm string
}

func main() {
	input, err := os.ReadFile("internal/design/BinaryEncoding.md")
	if err != nil {
		log.Fatal(err)
	}

	opcodes := make([]opcode, 256)

	for _, m := range re.FindAllStringSubmatch(string(input), -1) {
		i, err := strconv.ParseUint(m[2], 0, 8)
		if err != nil {
			panic(err)
		}

		opcodes[i] = opcode{
			name: m[1],
			sym:  symbol(m[1]),
			imm:  symbol(m[4]),
		}
	}

	generateFile("internal/gen/codegen/opcodes.go", forPackageCodegen, opcodes)
	generateFile("wa/opcode/opcodes.go", forPackageOpcode, opcodes)
}

func generateFile(filename string, generator func(func(string, ...any), []opcode), opcodes []opcode) {
	gofmt := os.Getenv("GOFMT")
	if gofmt == "" {
		gofmt = "gofmt"
	}

	cmd := exec.Command(gofmt)
	cmd.Stderr = os.Stderr

	w, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	r, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	defer func() {
		if cmd != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	genError := make(chan error, 1)
	go func() {
		err := errors.New("generation panic")
		defer func() {
			genError <- err
		}()

		defer w.Close()
		err = generateTo(w, generator, opcodes)
	}()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, r); err != nil {
		log.Fatal(err)
	}

	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
	cmd = nil

	if err := <-genError; err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(filename, buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}

func generateTo(w io.Writer, generator func(func(string, ...any), []opcode), opcodes []opcode) (err error) {
	defer func() {
		if x := recover(); x != nil {
			err = x.(error)
		}
	}()

	out := func(format string, args ...any) {
		if format == "}" {
			format += "\n"
		}

		if _, err := fmt.Fprintf(w, format+"\n", args...); err != nil {
			panic(err)
		}
	}

	out(`// Generated by internal/cmd/opcodes/generate.go`)
	out(``)

	generator(out, opcodes)
	return
}

func forPackageOpcode(out func(string, ...any), opcodes []opcode) {
	out(`package opcode`)

	out(`const (`)
	for code, op := range opcodes {
		if op.name != "" {
			out(`%s = Opcode(0x%02x)`, op.sym, code)
		}
	}
	out(`)`)

	out(`var strings = [256]string{`)
	for _, op := range opcodes {
		if op.name != "" {
			out(`%s: "%s",`, op.sym, op.name)
		}
	}
	out(`}`)
}

func forPackageCodegen(out func(string, ...any), opcodes []opcode) {
	out(`package codegen`)

	out(`import (`)
	out(`    "gate.computer/wag/internal/isa/prop"`)
	out(`    "gate.computer/wag/wa"`)
	out(`    "gate.computer/wag/wa/opcode"`)
	out(`)`)

	out(`var opcodeImpls = [256]opImpl{`)
	for code, op := range opcodes {
		switch op.name {
		case "":
			out(`0x%02x: {badGen, 0},`, code)

		case "block", "loop", "if":
			out(`opcode.%s: {nil, 0}, // initialized by init()`, op.sym)

		case "else":
			out(`opcode.%s: {badGen, 0},`, op.sym)

		case "end":
			out(`opcode.%s: {nil, 0},`, op.sym)

		case "i32.wrap/i64":
			out(`opcode.%s: {genWrap, 0},`, op.sym)

		default:
			if m := regexp.MustCompile(`^(...)\.const$`).FindStringSubmatch(op.name); m != nil {
				var (
					impl  = "genConst" + strings.ToUpper(m[1])
					type1 = "wa." + strings.ToUpper(m[1])
				)

				out(`opcode.%s: {%s, opInfo(%s)},`, op.sym, impl, type1)
			} else if m := regexp.MustCompile(`^(...)\.(.+)/(...)$`).FindStringSubmatch(op.name); m != nil {
				var (
					impl  = "genConvert"
					type1 = "wa." + strings.ToUpper(m[1])
					props = "prop." + symbol(m[2])
					type2 = "wa." + strings.ToUpper(m[3])
				)

				if m[2] == "reinterpret" {
					props += typeCategory(m[3][:1])
				}

				out(`opcode.%s: {%s, opInfo(%s) | (opInfo(%s) << 8) | (opInfo(%s) << 16)},`, op.sym, impl, type1, type2, props)
			} else if m := regexp.MustCompile(`^(.)(..)\.(load|store)([0-9]*)(.*)$`).FindStringSubmatch(op.name); m != nil {
				var (
					impl  = "gen" + symbol(m[3])
					type1 = "wa." + strings.ToUpper(m[1]+m[2])
				)

				accessBits := m[4]
				if accessBits == "" {
					accessBits = m[2]
				}

				n, err := strconv.Atoi(accessBits)
				if err != nil {
					log.Fatal(err)
				}
				maxAlign := int(math.Log2(float64(n / 8)))

				props := "prop." + strings.ToUpper(m[1]+m[2]) + symbol(m[3]+m[4]+m[5])

				out(`opcode.%s: {%s, opInfo(%s) | (opInfo(%d) << 8) | (opInfo(%s) << 16)},`, op.sym, impl, type1, maxAlign, props)
			} else if m := regexp.MustCompile(`^(.)(..)\.(.+)$`).FindStringSubmatch(op.name); m != nil {
				var (
					impl  = operGen(m[3])
					type1 = "wa." + strings.ToUpper(m[1]+m[2])
					props = "prop." + typeCategory(m[1]) + symbol(m[3])
				)

				out(`opcode.%s: {%s, opInfo(%s) | (opInfo(%s) << 16)},`, op.sym, impl, type1, props)
			} else {
				impl := "gen" + op.sym

				out(`opcode.%s: {%s, 0},`, op.sym, impl)
			}
		}
	}
	out(`}`)
}

func symbol(s string) string {
	s = strings.Replace(s, "_", ".", -1)
	s = strings.Title(s) //lint:ignore SA1019 works for ASCII
	s = strings.Replace(s, ".", "", -1)
	s = strings.Replace(s, "/", "", -1)
	return s
}

func typeCategory(letter string) string {
	switch letter {
	case "i":
		return "Int"

	case "f":
		return "Float"
	}

	panic(errors.New(letter))
}

func operGen(props string) string {
	switch props {
	case "abs", "ceil", "clz", "ctz", "eqz", "floor", "nearest", "neg", "popcnt", "sqrt", "trunc":
		return "genUnary"

	case "add", "and", "eq", "max", "min", "mul", "ne", "or", "xor":
		return "genBinaryCommute"

	case "copysign", "div", "div_s", "div_u", "ge", "ge_s", "ge_u", "gt", "gt_s", "gt_u", "le", "le_s", "le_u", "lt", "lt_s", "lt_u", "rem_s", "rem_u", "rotl", "rotr", "shl", "shr_s", "shr_u", "sub":
		return "genBinary"
	}

	panic(errors.New(props))
}
