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
	"github.com/tsavola/wag/internal/codegen"
	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/typeutil"
	"github.com/tsavola/wag/meta"
	"github.com/tsavola/wag/wasm"
)

type Env interface {
	ImportFunc(module, field string, sig abi.Sig) (variadic bool, absAddr uint64, err error)
	ImportGlobal(module, field string, t abi.Type) (valueBits uint64, err error)
}

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader = module.Reader

const (
	DefaultMemoryAlignment = 16 // see Module.MemoryAlignment
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

type Module struct {
	EntrySymbol          string
	EntryArgs            []uint64
	MemoryAlignment      int // see Data()
	Metadata             bool
	InsnMap              meta.InsnMap
	UnknownSectionLoader func(r Reader, payloadLen uint32) error

	module.M
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
	loadUntil(m, loader.L{Reader: r}, env, module.SectionCode)
}

// Load all (remaining) sections.
func (m *Module) Load(r Reader, env Env, text TextBuffer, roData DataBuffer, roDataAddr int32, data DataBuffer) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.load(r, env, text, roData, roDataAddr, data)
	return
}

func (m *Module) load(r Reader, env Env, text TextBuffer, roData DataBuffer, roDataAddr int32, data DataBuffer) {
	if text == nil {
		text = new(defaultBuffer)
	}
	if roData == nil {
		roData = new(defaultBuffer)
	}
	if data == nil {
		data = new(defaultBuffer)
	}

	m.M.Text = text
	m.M.ROData = roData
	m.M.RODataAddr = roDataAddr
	m.M.Data = data

	load(m, loader.L{Reader: r}, env)
}

func readTable(m *Module, load loader.L) {
	if m.TableLimitValues.Defined {
		panic(errors.New("multiple tables not supported"))
	}

	if elementType := load.Varint7(); elementType != -0x10 {
		panic(fmt.Errorf("unsupported table element type: %d", elementType))
	}

	m.TableLimitValues = readResizableLimits(load, maxTableLimit, maxTableLimit, 1)
}

func readMemory(m *Module, load loader.L) {
	if m.MemoryLimitValues.Defined {
		panic(errors.New("multiple memories not supported"))
	}

	m.MemoryLimitValues = readResizableLimits(load, maxInitialMemoryLimit, maxMaximumMemoryLimit, int(wasm.Page))
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
				sig.Args[j] = typeutil.ValueTypeByEncoding(load.Varint7())
			}

			if returnCount1 := load.Varuint1(); returnCount1 {
				sig.Result = typeutil.ValueTypeByEncoding(load.Varint7())
			}

			m.M.Sigs = append(m.M.Sigs, sig)
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
				if sigIndex >= uint32(len(m.M.Sigs)) {
					panic(fmt.Errorf("function type index out of bounds in import #%d: 0x%x", i, sigIndex))
				}

				sig := m.M.Sigs[sigIndex]
				if n := len(sig.Args); n > codegen.MaxImportParams {
					panic(fmt.Errorf("import function #%d has too many parameters: %d", i, n))
				}

				funcIndex := len(m.M.FuncSigs)
				m.M.FuncSigs = append(m.M.FuncSigs, sigIndex)

				variadic, absAddr, err := env.ImportFunc(moduleStr, fieldStr, sig)
				if err != nil {
					panic(err)
				}

				m.ImportFuncs = append(m.ImportFuncs, module.ImportFunc{
					FuncIndex: funcIndex,
					Variadic:  variadic,
					AbsAddr:   absAddr,
				})

			case module.ExternalKindTable:
				readTable(m, load)

			case module.ExternalKindMemory:
				readMemory(m, load)

			case module.ExternalKindGlobal:
				if len(m.Globals) >= maxGlobals {
					panic(errors.New("too many imported globals"))
				}

				t := typeutil.ValueTypeByEncoding(load.Varint7())

				mutable := load.Varuint1()
				if mutable {
					panic(fmt.Errorf("unsupported mutable global in import #%d", i))
				}

				init, err := env.ImportGlobal(moduleStr, fieldStr, t)
				if err != nil {
					panic(err)
				}

				m.Globals = append(m.Globals, module.Global{
					Type:    t,
					Mutable: mutable,
					Init:    init,
				})

			default:
				panic(fmt.Errorf("import kind not supported: %s", kind))
			}
		}

		m.NumImportGlobals = len(m.Globals)
	},

	module.SectionFunction: func(m *Module, load loader.L, env Env) {
		for range load.Count() {
			sigIndex := load.Varuint32()
			if sigIndex >= uint32(len(m.M.Sigs)) {
				panic(fmt.Errorf("function type index out of bounds: %d", sigIndex))
			}

			m.M.FuncSigs = append(m.M.FuncSigs, sigIndex)
		}
	},

	module.SectionTable: func(m *Module, load loader.L, env Env) {
		for range load.Count() {
			readTable(m, load)
		}
	},

	module.SectionMemory: func(m *Module, load loader.L, env Env) {
		for range load.Count() {
			readMemory(m, load)
		}
	},

	module.SectionGlobal: func(m *Module, load loader.L, env Env) {
		for range load.Count() {
			if len(m.Globals) >= maxGlobals {
				panic(errors.New("too many globals"))
			}

			t := typeutil.ValueTypeByEncoding(load.Varint7())
			mutable := load.Varuint1()
			init, _ := readInitExpr(m, load)

			m.Globals = append(m.Globals, module.Global{
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
					if index >= uint32(len(m.M.FuncSigs)) {
						panic(fmt.Errorf("export function index out of bounds: %d", index))
					}

					sigIndex := m.M.FuncSigs[index]
					sig := m.M.Sigs[sigIndex]
					if len(sig.Args) > codegen.MaxEntryParams || len(m.EntryArgs) < len(sig.Args) || !(sig.Result == abi.Void || sig.Result == abi.I32) {
						panic(fmt.Errorf("invalid entry function signature: %s %s", m.EntrySymbol, sig))
					}

					m.EntryIndex = index
					m.EntryDefined = true
				}

			case module.ExternalKindTable, module.ExternalKindMemory, module.ExternalKindGlobal:

			default:
				panic(fmt.Errorf("unknown export kind: %s", kind))
			}
		}
	},

	module.SectionStart: func(m *Module, load loader.L, env Env) {
		index := load.Varuint32()
		if index >= uint32(len(m.M.FuncSigs)) {
			panic(fmt.Errorf("start function index out of bounds: %d", index))
		}

		sigIndex := m.M.FuncSigs[index]
		sig := m.M.Sigs[sigIndex]
		if len(sig.Args) > 0 || sig.Result != abi.Void {
			panic(fmt.Errorf("invalid start function signature: %s", sig))
		}

		m.StartIndex = index
		m.StartDefined = true
	},

	module.SectionElement: func(m *Module, load loader.L, env Env) {
		for i := range load.Count() {
			if index := load.Varuint32(); index != 0 {
				panic(fmt.Errorf("unsupported table index: %d", index))
			}

			offset := readOffsetInitExpr(m, load)

			numElem := load.Varuint32()

			needSize := uint64(offset) + uint64(numElem)
			if needSize > uint64(m.TableLimitValues.Initial) {
				panic(fmt.Errorf("table segment #%d exceeds initial table size", i))
			}

			oldSize := len(m.TableFuncs)
			if needSize > uint64(oldSize) {
				buf := make([]uint32, needSize)
				copy(buf, m.TableFuncs)
				for i := oldSize; i < int(offset); i++ {
					buf[i] = math.MaxInt32 // invalid function index
				}
				m.TableFuncs = buf
			}

			for j := int(offset); j < int(needSize); j++ {
				elem := load.Varuint32()
				if elem >= uint32(len(m.M.FuncSigs)) {
					panic(fmt.Errorf("table element index out of bounds: %d", elem))
				}

				m.TableFuncs[j] = elem
			}
		}
	},

	module.SectionCode: func(m *Module, load loader.L, env Env) {
		genCode(m, load, nil)
	},

	module.SectionData: func(m *Module, load loader.L, env Env) {
		genDataGlobals(m)
		genDataMemory(m, load)
	},
}

// LoadCodeSection, after loading the preliminary sections.
func (m *Module) LoadCodeSection(r Reader, text TextBuffer, roData DataBuffer, roDataAddr int32, startTrigger chan<- struct{}) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadCodeSection(r, text, roData, roDataAddr, startTrigger)
	return
}

func (m *Module) loadCodeSection(r Reader, text TextBuffer, roData DataBuffer, roDataAddr int32, startTrigger chan<- struct{}) {
	if m.FuncLinks != nil {
		panic(errors.New("code section has already been loaded"))
	}

	if text == nil {
		text = new(defaultBuffer)
	}
	if roData == nil {
		roData = new(defaultBuffer)
	}

	m.M.Text = text
	m.M.ROData = roData
	m.M.RODataAddr = roDataAddr

	load := loader.L{Reader: r}

	if readSectionHeader(load, module.SectionCode, "not a code section") {
		genCode(m, load, startTrigger)
	}
}

func genCode(m *Module, load loader.L, startTrigger chan<- struct{}) {
	if m.EntrySymbol != "" && !m.EntryDefined {
		panic(fmt.Errorf("%s function not found in export section", m.EntrySymbol))
	}

	if m.Metadata || m.InsnMap != nil {
		m.M.FuncMap = make([]meta.TextAddr, 0, len(m.M.FuncSigs))
	}

	if m.Metadata {
		m.M.CallMap = make([]meta.CallSite, 0, len(m.M.FuncSigs)) // conservative estimate...
	}

	insnMap := m.InsnMap
	if insnMap == nil {
		insnMap = dummyInsnMap{}
	}

	codegen.GenProgram(&m.M, load, m.EntryDefined, m.EntrySymbol, m.EntryArgs, startTrigger, insnMap)
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
	if m.M.Data != nil {
		panic(errors.New("data section has already been loaded"))
	}

	if data == nil {
		data = new(defaultBuffer)
	}
	m.M.Data = data

	genDataGlobals(m)

	load := loader.L{Reader: r}

	if readSectionHeader(load, module.SectionData, "not a data section") {
		genDataMemory(m, load)
	}
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

// Sigs are available after preliminary sections have been loaded.
func (m *Module) Sigs() []abi.Sig {
	return m.M.Sigs
}

// FuncSigs are available after preliminary sections have been loaded.
func (m *Module) FuncSigs() (funcSigs []abi.Sig) {
	funcSigs = make([]abi.Sig, len(m.M.FuncSigs))
	for i, sigIndex := range m.M.FuncSigs {
		funcSigs[i] = m.M.Sigs[sigIndex]
	}
	return
}

// MemoryLimits are available after preliminary sections have been loaded.
func (m *Module) MemoryLimits() (initial, maximum wasm.MemorySize) {
	initial = wasm.MemorySize(m.MemoryLimitValues.Initial)
	maximum = wasm.MemorySize(m.MemoryLimitValues.Maximum)
	return
}

// GlobalsSize is available after preliminary sections have been loaded.
func (m *Module) GlobalsSize() int {
	return len(m.Globals) * gen.WordSize
}

// Text is available after code section has been loaded.
func (m *Module) Text() (b []byte) {
	if m.M.Text != nil {
		b = m.M.Text.Bytes()
	}
	return
}

// ROData is available after code section has been loaded.
func (m *Module) ROData() (b []byte) {
	if m.M.ROData != nil {
		b = m.M.ROData.Bytes()
	}
	return
}

// FuncMap is available after code section has been loaded and either Metadata
// or InsnMap was set before that.  The function addresses are in ascending
// order.
func (m *Module) FuncMap() []meta.TextAddr {
	return m.M.FuncMap
}

// CallMap is available after code section has been loaded and Metadata was set
// before that.  The call sites are in ascending order.
func (m *Module) CallMap() []meta.CallSite {
	return m.M.CallMap
}

// Data is available after data section has been loaded.  memoryOffset is an
// offset into data.  It will be a multiple of MemoryAlignment.
func (m *Module) Data() (data []byte, memoryOffset int) {
	if m.M.Data == nil {
		m.M.Data = new(defaultBuffer)
	}

	if len(m.Globals) > 0 && m.MemoryOffset == 0 {
		// simple program without data section, but has globals
		genDataGlobals(m)
	}

	data = m.M.Data.Bytes()
	memoryOffset = m.MemoryOffset
	return
}
