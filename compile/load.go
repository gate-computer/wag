// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/datalayout"
	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/gen/codegen"
	"github.com/tsavola/wag/internal/initexpr"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/internal/reader"
	"github.com/tsavola/wag/internal/typedecode"
	"github.com/tsavola/wag/wasm"
)

type Env interface {
	ImportFunc(module, field string, sig abi.Sig) (variadic bool, absAddr uint64, err error)
	ImportGlobal(module, field string, t abi.Type) (valueBits uint64, err error)
}

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader = reader.R

const (
	DefaultMemoryAlignment = datalayout.DefaultAlignment // see Module.MemoryAlignment
)

const (
	maxStringLen          = 255   // TODO
	maxTableLimit         = 32768 // TODO
	maxInitialMemoryLimit = 16384 // TODO
	maxMaximumMemoryLimit = math.MaxInt32 >> wasm.PageBits
	maxGlobals            = 512 // 4096 bytes
)

func readResizableLimits(load loader.L, maxInitial, maxMaximum uint32, scale int) module.ResizableLimits {
	maximumFieldIsPresent := load.Varuint1()

	initial := load.Varuint32()
	if initial > maxInitial {
		panic(fmt.Errorf("initial memory size is too large: %d", initial))
	}

	maximum := maxMaximum

	if maximumFieldIsPresent {
		maximum = load.Varuint32()
		if maximum > maxMaximum {
			maximum = maxMaximum
		}
		if maximum < initial {
			panic(fmt.Errorf("maximum memory size %d is smaller than initial memory size %d", maximum, initial))
		}
	}

	return module.ResizableLimits{
		Initial: int(initial) * scale,
		Maximum: int(maximum) * scale,
		Defined: true,
	}
}

func readTable(m *module.M, load loader.L) {
	if m.TableLimitValues.Defined {
		panic(errors.New("multiple tables not supported"))
	}

	if elementType := load.Varint7(); elementType != -0x10 {
		panic(fmt.Errorf("unsupported table element type: %d", elementType))
	}

	m.TableLimitValues = readResizableLimits(load, maxTableLimit, maxTableLimit, 1)
}

func readMemory(m *module.M, load loader.L) {
	if m.MemoryLimitValues.Defined {
		panic(errors.New("multiple memories not supported"))
	}

	m.MemoryLimitValues = readResizableLimits(load, maxInitialMemoryLimit, maxMaximumMemoryLimit, int(wasm.Page))
}

func readSectionHeader(load loader.L, expectId byte, idError string) (ok bool) {
	id, err := load.ReadByte()
	if err != nil {
		if err == io.EOF {
			return
		}
		panic(err)
	}

	if id != expectId {
		panic(errors.New(idError))
	}

	load.Varuint32() // payload len

	ok = true
	return
}

type Module struct {
	EntrySymbol          string
	EntryArgs            []uint64
	MemoryAlignment      int // see Data()
	UnknownSectionLoader func(r Reader, payloadLen uint32) error

	m module.M
}

// LoadPreliminarySections, excluding the code and data sections.
func (m *Module) LoadPreliminarySections(r Reader, env Env) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadPreliminarySections(r, env)
	return
}

func (m *Module) loadPreliminarySections(r Reader, env Env) {
	loadUntil(m, loader.L{R: r}, env, module.SectionCode)
}

// Load all (remaining) sections.
func (m *Module) Load(r Reader, env Env, text TextBuffer, roData DataBuffer, roDataAddr int32, data DataBuffer, objMap ObjectMap) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.load(r, env, text, roData, roDataAddr, data, objMap)
	return
}

func (m *Module) load(r Reader, env Env, text TextBuffer, roData DataBuffer, roDataAddr int32, data DataBuffer, objMap ObjectMap) {
	if text == nil {
		text = new(defaultBuffer)
	}
	if roData == nil {
		roData = new(defaultBuffer)
	}
	if data == nil {
		data = new(defaultBuffer)
	}
	if objMap == nil {
		objMap = dummyMap{}
	}

	m.m.Text = code.Buf{Buffer: text}
	m.m.ROData = roData
	m.m.RODataAddr = roDataAddr
	m.m.Data = data
	m.m.Map = objMap

	load(m, loader.L{R: r}, env)
}

func load(m *Module, load loader.L, env Env) {
	nextId := loadUntil(m, load, env, module.NumSections)
	if nextId != 0 {
		panic(fmt.Errorf("unknown section id: 0x%x", nextId))
	}
}

func loadUntil(m *Module, load loader.L, env Env, untilSection byte) byte {
	var header module.Header
	if err := binary.Read(load, binary.LittleEndian, &header); err != nil {
		panic(err)
	}
	if header.MagicNumber != module.MagicNumber {
		panic(errors.New("not a WebAssembly module"))
	}
	if header.Version != module.Version {
		panic(fmt.Errorf("unsupported module version: %d", header.Version))
	}

	var skipSection func(byte, uint32) error

	if m.UnknownSectionLoader != nil {
		skipSection = func(id byte, payloadLen uint32) (err error) {
			if id == module.SectionUnknown {
				err = m.UnknownSectionLoader(load, payloadLen)
			} else {
				_, err = io.CopyN(ioutil.Discard, load, int64(payloadLen))
			}
			return
		}
	} else {
		skipSection = func(id byte, payloadLen uint32) (err error) {
			_, err = io.CopyN(ioutil.Discard, load, int64(payloadLen))
			return
		}
	}

	var seenId byte

	for {
		id, err := load.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0
			}
			panic(err)
		}

		if id != module.SectionUnknown {
			if id <= seenId {
				panic(fmt.Errorf("section 0x%x follows section 0x%x", id, seenId))
			}
			seenId = id
		}

		if id >= untilSection {
			load.UnreadByte()
			return id
		}

		payloadLen := load.Varuint32()

		if f := sectionLoaders[id]; f != nil {
			f(m, load, env)
		} else if err := skipSection(id, payloadLen); err != nil {
			panic(err)
		}
	}
}

var sectionLoaders = []func(*Module, loader.L, Env){
	module.SectionType: func(m *Module, load loader.L, env Env) {
		for i := range load.Count() {
			if form := load.Varint7(); form != -0x20 {
				panic(fmt.Errorf("unsupported function type form: %d", form))
			}

			var sig abi.Sig

			paramCount := load.Varuint32()
			if paramCount > codegen.MaxFuncParams {
				panic(fmt.Errorf("function type #%d has too many parameters: %d", i, paramCount))
			}

			sig.Args = make([]abi.Type, paramCount)
			for j := range sig.Args {
				sig.Args[j] = typedecode.Value(load.Varint7())
			}

			if returnCount1 := load.Varuint1(); returnCount1 {
				sig.Result = typedecode.Value(load.Varint7())
			}

			m.m.Sigs = append(m.m.Sigs, sig)
		}
	},

	module.SectionImport: func(m *Module, load loader.L, env Env) {
		for i := range load.Count() {
			moduleLen := load.Varuint32()
			if moduleLen > maxStringLen {
				panic(fmt.Errorf("module string is too long in import #%d", i))
			}

			moduleStr := string(load.Bytes(moduleLen))

			fieldLen := load.Varuint32()
			if fieldLen > maxStringLen {
				panic(fmt.Errorf("field string is too long in import #%d", i))
			}

			fieldStr := string(load.Bytes(fieldLen))

			kind := module.ExternalKind(load.Byte())

			switch kind {
			case module.ExternalKindFunction:
				sigIndex := load.Varuint32()
				if sigIndex >= uint32(len(m.m.Sigs)) {
					panic(fmt.Errorf("function type index out of bounds in import #%d: 0x%x", i, sigIndex))
				}

				sig := m.m.Sigs[sigIndex]
				if n := len(sig.Args); n > codegen.MaxImportParams {
					panic(fmt.Errorf("import function #%d has too many parameters: %d", i, n))
				}

				funcIndex := len(m.m.FuncSigs)
				m.m.FuncSigs = append(m.m.FuncSigs, sigIndex)

				variadic, absAddr, err := env.ImportFunc(moduleStr, fieldStr, sig)
				if err != nil {
					panic(err)
				}

				m.m.ImportFuncs = append(m.m.ImportFuncs, module.ImportFunc{
					FuncIndex: funcIndex,
					Variadic:  variadic,
					AbsAddr:   absAddr,
				})

			case module.ExternalKindTable:
				readTable(&m.m, load)

			case module.ExternalKindMemory:
				readMemory(&m.m, load)

			case module.ExternalKindGlobal:
				if len(m.m.Globals) >= maxGlobals {
					panic(errors.New("too many imported globals"))
				}

				t := typedecode.Value(load.Varint7())

				mutable := load.Varuint1()
				if mutable {
					panic(fmt.Errorf("unsupported mutable global in import #%d", i))
				}

				init, err := env.ImportGlobal(moduleStr, fieldStr, t)
				if err != nil {
					panic(err)
				}

				m.m.Globals = append(m.m.Globals, module.Global{
					Type:    t,
					Mutable: mutable,
					Init:    init,
				})

			default:
				panic(fmt.Errorf("import kind not supported: %s", kind))
			}
		}

		m.m.NumImportGlobals = len(m.m.Globals)
	},

	module.SectionFunction: func(m *Module, load loader.L, env Env) {
		for range load.Count() {
			sigIndex := load.Varuint32()
			if sigIndex >= uint32(len(m.m.Sigs)) {
				panic(fmt.Errorf("function type index out of bounds: %d", sigIndex))
			}

			m.m.FuncSigs = append(m.m.FuncSigs, sigIndex)
		}
	},

	module.SectionTable: func(m *Module, load loader.L, env Env) {
		for range load.Count() {
			readTable(&m.m, load)
		}
	},

	module.SectionMemory: func(m *Module, load loader.L, env Env) {
		for range load.Count() {
			readMemory(&m.m, load)
		}
	},

	module.SectionGlobal: func(m *Module, load loader.L, env Env) {
		for range load.Count() {
			if len(m.m.Globals) >= maxGlobals {
				panic(errors.New("too many globals"))
			}

			t := typedecode.Value(load.Varint7())
			mutable := load.Varuint1()
			init, _ := initexpr.Read(&m.m, load)

			m.m.Globals = append(m.m.Globals, module.Global{
				Type:    t,
				Mutable: mutable,
				Init:    init,
			})
		}
	},

	module.SectionExport: func(m *Module, load loader.L, env Env) {
		for i := range load.Count() {
			fieldLen := load.Varuint32()
			if fieldLen > maxStringLen {
				panic(fmt.Errorf("field string is too long in export #%d", i))
			}

			fieldStr := load.Bytes(fieldLen)
			kind := module.ExternalKind(load.Byte())
			index := load.Varuint32()

			switch kind {
			case module.ExternalKindFunction:
				if fieldLen > 0 && string(fieldStr) == m.EntrySymbol {
					if index >= uint32(len(m.m.FuncSigs)) {
						panic(fmt.Errorf("export function index out of bounds: %d", index))
					}

					sigIndex := m.m.FuncSigs[index]
					sig := m.m.Sigs[sigIndex]
					if len(sig.Args) > codegen.MaxEntryParams || len(m.EntryArgs) < len(sig.Args) || !(sig.Result == abi.Void || sig.Result == abi.I32) {
						panic(fmt.Errorf("invalid entry function signature: %s %s", m.EntrySymbol, sig))
					}

					m.m.EntryIndex = index
					m.m.EntryDefined = true
				}

			case module.ExternalKindTable, module.ExternalKindMemory, module.ExternalKindGlobal:

			default:
				panic(fmt.Errorf("unknown export kind: %s", kind))
			}
		}
	},

	module.SectionStart: func(m *Module, load loader.L, env Env) {
		index := load.Varuint32()
		if index >= uint32(len(m.m.FuncSigs)) {
			panic(fmt.Errorf("start function index out of bounds: %d", index))
		}

		sigIndex := m.m.FuncSigs[index]
		sig := m.m.Sigs[sigIndex]
		if len(sig.Args) > 0 || sig.Result != abi.Void {
			panic(fmt.Errorf("invalid start function signature: %s", sig))
		}

		m.m.StartIndex = index
		m.m.StartDefined = true
	},

	module.SectionElement: func(m *Module, load loader.L, env Env) {
		for i := range load.Count() {
			if index := load.Varuint32(); index != 0 {
				panic(fmt.Errorf("unsupported table index: %d", index))
			}

			offset := initexpr.ReadOffset(&m.m, load)

			numElem := load.Varuint32()

			needSize := uint64(offset) + uint64(numElem)
			if needSize > uint64(m.m.TableLimitValues.Initial) {
				panic(fmt.Errorf("table segment #%d exceeds initial table size", i))
			}

			oldSize := len(m.m.TableFuncs)
			if needSize > uint64(oldSize) {
				buf := make([]uint32, needSize)
				copy(buf, m.m.TableFuncs)
				for i := oldSize; i < int(offset); i++ {
					buf[i] = math.MaxInt32 // invalid function index
				}
				m.m.TableFuncs = buf
			}

			for j := int(offset); j < int(needSize); j++ {
				elem := load.Varuint32()
				if elem >= uint32(len(m.m.FuncSigs)) {
					panic(fmt.Errorf("table element index out of bounds: %d", elem))
				}

				m.m.TableFuncs[j] = elem
			}
		}
	},

	module.SectionCode: func(m *Module, load loader.L, env Env) {
		genCode(m, load, nil)
	},

	module.SectionData: func(m *Module, load loader.L, env Env) {
		datalayout.CopyGlobals(&m.m, m.MemoryAlignment)
		datalayout.ReadMemory(&m.m, load)
	},
}

// LoadCodeSection, after loading the preliminary sections.
func (m *Module) LoadCodeSection(r Reader, text TextBuffer, roData DataBuffer, roDataAddr int32, objMap ObjectMap, startTrigger chan<- struct{}) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadCodeSection(r, text, roData, roDataAddr, objMap, startTrigger)
	return
}

func (m *Module) loadCodeSection(r Reader, text TextBuffer, roData DataBuffer, roDataAddr int32, objMap ObjectMap, startTrigger chan<- struct{}) {
	if text == nil {
		text = new(defaultBuffer)
	}
	if roData == nil {
		roData = new(defaultBuffer)
	}
	if objMap == nil {
		objMap = dummyMap{}
	}

	m.m.Text = code.Buf{Buffer: text}
	m.m.ROData = roData
	m.m.RODataAddr = roDataAddr
	m.m.Map = objMap

	load := loader.L{R: r}

	if readSectionHeader(load, module.SectionCode, "not a code section") {
		genCode(m, load, startTrigger)
	}
}

// LoadDataSection, after loading the preliminary sections.
func (m *Module) LoadDataSection(r Reader, data DataBuffer) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadDataSection(r, data)
	return
}

func (m *Module) loadDataSection(r Reader, data DataBuffer) {
	if m.m.Data != nil {
		panic(errors.New("data section has already been loaded"))
	}

	if data == nil {
		data = new(defaultBuffer)
	}
	m.m.Data = data

	datalayout.CopyGlobals(&m.m, m.MemoryAlignment)

	load := loader.L{R: r}

	if readSectionHeader(load, module.SectionData, "not a data section") {
		datalayout.ReadMemory(&m.m, load)
	}
}

// Sigs are available after preliminary sections have been loaded.
func (m *Module) Sigs() []abi.Sig {
	return m.m.Sigs
}

// FuncSigs are available after preliminary sections have been loaded.
func (m *Module) FuncSigs() (funcSigs []abi.Sig) {
	funcSigs = make([]abi.Sig, len(m.m.FuncSigs))
	for i, sigIndex := range m.m.FuncSigs {
		funcSigs[i] = m.m.Sigs[sigIndex]
	}
	return
}

// MemoryLimits are available after preliminary sections have been loaded.
func (m *Module) MemoryLimits() (initial, maximum wasm.MemorySize) {
	initial = wasm.MemorySize(m.m.MemoryLimitValues.Initial)
	maximum = wasm.MemorySize(m.m.MemoryLimitValues.Maximum)
	return
}

// GlobalsSize is available after preliminary sections have been loaded.
func (m *Module) GlobalsSize() int {
	return len(m.m.Globals) * obj.Word
}

// Text is available after code section has been loaded.
func (m *Module) Text() (b []byte) {
	if m.m.Text.Buffer != nil {
		b = m.m.Text.Buffer.Bytes()
	}
	return
}

// ROData is available after code section has been loaded.
func (m *Module) ROData() (b []byte) {
	if m.m.ROData != nil {
		b = m.m.ROData.Bytes()
	}
	return
}

// Data is available after data section has been loaded.  memoryOffset is an
// offset into data.  It will be a multiple of MemoryAlignment.
func (m *Module) Data() (data []byte, memoryOffset int) {
	if m.m.Data == nil {
		m.m.Data = new(defaultBuffer)
	}

	if len(m.m.Globals) > 0 && m.m.MemoryOffset == 0 {
		// simple program without data section, but has globals
		datalayout.CopyGlobals(&m.m, m.MemoryAlignment)
	}

	data = m.m.Data.Bytes()
	memoryOffset = m.m.MemoryOffset
	return
}

func genCode(m *Module, load loader.L, startTrigger chan<- struct{}) {
	if m.EntrySymbol != "" && !m.m.EntryDefined {
		panic(fmt.Errorf("%s function not found in export section", m.EntrySymbol))
	}

	codegen.GenProgram(&m.m, load, m.EntrySymbol, m.EntryArgs, startTrigger)
}
