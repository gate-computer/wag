// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"

	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/sectionids"
	"github.com/tsavola/wag/reader"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/types"
	"github.com/tsavola/wag/wasm"
)

type Environment interface {
	ImportFunction(module, field string, sig types.Function) (variadic bool, absAddr uint64, err error)
	ImportGlobal(module, field string, t types.T) (valueBits uint64, err error)
}

type Buffer interface {
	io.Writer
	io.ByteWriter

	Bytes() []byte
	Grow(n int)
	Len() int
}

type InsnMap interface {
	Init(numFuncs int)
	PutFunc(pos int32)
	PutInsn(pos int32)
}

const (
	maxStringLen          = 255 // TODO
	maxImportParams       = gen.StackReserve/gen.WordSize - 2
	maxFunctionParams     = 255   // index+1 must fit in uint8
	maxFunctionVars       = 511   // index must fit in uint16; TODO
	maxTableLimit         = 32768 // TODO
	maxInitialMemoryLimit = 256   // TODO
	maxMaximumMemoryLimit = math.MaxInt32 >> wasm.PageBits
	maxBranchTableSize    = 32768 // TODO
)

type externalKind byte

const (
	externalKindFunction = externalKind(iota)
	externalKindTable
	externalKindMemory
	externalKindGlobal
)

var externalKindStrings = []string{
	externalKindFunction: "function",
	externalKindTable:    "table",
	externalKindMemory:   "memory",
	externalKindGlobal:   "global",
}

func (kind externalKind) String() (s string) {
	if int(kind) < len(externalKindStrings) {
		s = externalKindStrings[kind]
	} else {
		s = fmt.Sprintf("<unknown external kind 0x%x>", byte(kind))
	}
	return
}

type resizableLimits struct {
	initial int
	maximum int
	defined bool
}

func readResizableLimits(load loader.L, maxInitial, maxMaximum uint32, scale int) resizableLimits {
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

	return resizableLimits{int(initial) * scale, int(maximum) * scale, true}
}

const (
	moduleMagicNumber = uint32(0x6d736100)
	moduleVersion     = uint32(1)
)

type importFunction struct {
	funcIndex int
	variadic  bool
	absAddr   uint64
}

type global struct {
	t       types.T
	mutable bool
	init    uint64
}

func appendGlobalsData(buf []byte, globals []global) []byte {
	oldSize := len(buf)
	newSize := oldSize + len(globals)*gen.WordSize

	if cap(buf) >= newSize {
		buf = buf[:newSize]
	} else {
		newBuf := make([]byte, newSize)
		copy(newBuf, buf)
		buf = newBuf
	}

	ptr := buf[oldSize:]

	for _, global := range globals {
		binary.LittleEndian.PutUint64(ptr, global.init)
		ptr = ptr[8:]
	}

	return buf
}

type Module struct {
	EntrySymbol          string
	UnknownSectionLoader func(r reader.Reader, payloadLen uint32) error
	InsnMap              InsnMap

	sigs             []types.Function
	funcSigs         []uint32
	importFuncs      []importFunction
	tableLimits      resizableLimits
	memoryLimits     resizableLimits
	globals          []global
	numImportGlobals int
	entryIndex       uint32
	entryDefined     bool
	startIndex       uint32
	startDefined     bool
	tableFuncs       []uint32

	text          Buffer
	roDataAbsAddr int32
	roData        dataArena
	trapLinks     [traps.NumTraps]links.L
	funcLinks     []links.FunctionL
	funcMap       bytes.Buffer
	callMap       bytes.Buffer
	regs          regAllocator

	data         []byte
	memoryOffset int
}

// LoadPreliminarySections, excluding the code and data sections.
func (m *Module) LoadPreliminarySections(r reader.Reader, env Environment) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadPreliminarySections(r, env)
	return
}

func (m *Module) loadPreliminarySections(r reader.Reader, env Environment) {
	moduleLoader{m, env, nil}.loadUntil(loader.L{Reader: r}, sectionids.Code)
}

// Load all (remaining) sections.
func (m *Module) Load(r reader.Reader, env Environment, textBuf Buffer, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.load(r, env, textBuf, roDataBuf, roDataAbsAddr, startTrigger)
	return
}

func (m *Module) load(r reader.Reader, env Environment, textBuf Buffer, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) {
	m.text = textBuf
	m.roData.buf = roDataBuf[:0]
	m.roDataAbsAddr = roDataAbsAddr

	moduleLoader{m, env, startTrigger}.load(loader.L{Reader: r})
}

type moduleLoader struct {
	*Module
	env          Environment
	startTrigger chan<- struct{}
}

func (m moduleLoader) load(load loader.L) {
	nextId := m.loadUntil(load, sectionids.NumSections)
	if nextId != 0 {
		panic(fmt.Errorf("unknown section id: 0x%x", nextId))
	}
}

func (m moduleLoader) loadUntil(load loader.L, untilSection byte) byte {
	var header struct {
		MagicNumber uint32
		Version     uint32
	}
	if err := binary.Read(load, binary.LittleEndian, &header); err != nil {
		panic(err)
	}
	if header.MagicNumber != moduleMagicNumber {
		panic(errors.New("not a WebAssembly module"))
	}
	if header.Version != moduleVersion {
		panic(fmt.Errorf("unsupported module version: %d", header.Version))
	}

	var skipSection func(byte, uint32) error

	if m.UnknownSectionLoader != nil {
		skipSection = func(id byte, payloadLen uint32) (err error) {
			if id == sectionids.Unknown {
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

		if id != sectionids.Unknown {
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
			f(m, load)
		} else if err := skipSection(id, payloadLen); err != nil {
			panic(err)
		}
	}
}

var sectionLoaders = []func(moduleLoader, loader.L){
	sectionids.Type: func(m moduleLoader, load loader.L) {
		for i := range load.Count() {
			if form := load.Varint7(); form != -0x20 {
				panic(fmt.Errorf("unsupported function type form: %d", form))
			}

			var sig types.Function

			paramCount := load.Varuint32()
			if paramCount > maxFunctionParams {
				panic(fmt.Errorf("function type #%d has too many parameters: %d", i, paramCount))
			}

			sig.Args = make([]types.T, paramCount)
			for j := range sig.Args {
				sig.Args[j] = types.ByEncoding(load.Varint7())
			}

			if returnCount1 := load.Varuint1(); returnCount1 {
				sig.Result = types.ByEncoding(load.Varint7())
			}

			m.sigs = append(m.sigs, sig)
		}
	},

	sectionids.Import: func(m moduleLoader, load loader.L) {
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

			kind := externalKind(load.Byte())

			switch kind {
			case externalKindFunction:
				sigIndex := load.Varuint32()
				if sigIndex >= uint32(len(m.sigs)) {
					panic(fmt.Errorf("function type index out of bounds in import #%d: 0x%x", i, sigIndex))
				}

				sig := m.sigs[sigIndex]
				if n := len(sig.Args); n > maxImportParams {
					panic(fmt.Errorf("import function #%d has too many parameters: %d", i, n))
				}

				funcIndex := len(m.funcSigs)
				m.funcSigs = append(m.funcSigs, sigIndex)

				variadic, absAddr, err := m.env.ImportFunction(moduleStr, fieldStr, sig)
				if err != nil {
					panic(err)
				}

				m.importFuncs = append(m.importFuncs, importFunction{
					funcIndex: funcIndex,
					variadic:  variadic,
					absAddr:   absAddr,
				})

			case externalKindGlobal:
				t := types.ByEncoding(load.Varint7())

				mutable := load.Varuint1()
				if mutable {
					panic(fmt.Errorf("unsupported mutable global in import #%d", i))
				}

				init, err := m.env.ImportGlobal(moduleStr, fieldStr, t)
				if err != nil {
					panic(err)
				}

				m.globals = append(m.globals, global{t, mutable, init})

			default:
				panic(fmt.Errorf("import kind not supported: %s", kind))
			}
		}

		m.numImportGlobals = len(m.globals)

		m.data = appendGlobalsData(m.data, m.globals)
		m.memoryOffset = len(m.data)
	},

	sectionids.Function: func(m moduleLoader, load loader.L) {
		for range load.Count() {
			sigIndex := load.Varuint32()
			if sigIndex >= uint32(len(m.sigs)) {
				panic(fmt.Errorf("function type index out of bounds: %d", sigIndex))
			}

			m.funcSigs = append(m.funcSigs, sigIndex)
		}
	},

	sectionids.Table: func(m moduleLoader, load loader.L) {
		for range load.Count() {
			if m.tableLimits.defined {
				panic(errors.New("multiple tables not supported"))
			}

			if elementType := load.Varint7(); elementType != -0x10 {
				panic(fmt.Errorf("unsupported table element type: %d", elementType))
			}

			m.tableLimits = readResizableLimits(load, maxTableLimit, maxTableLimit, 1)
		}
	},

	sectionids.Memory: func(m moduleLoader, load loader.L) {
		for range load.Count() {
			if m.memoryLimits.defined {
				panic(errors.New("multiple memories not supported"))
			}

			m.memoryLimits = readResizableLimits(load, maxInitialMemoryLimit, maxMaximumMemoryLimit, int(wasm.Page))
		}
	},

	sectionids.Global: func(m moduleLoader, load loader.L) {
		// TODO: limit number of globals
		for range load.Count() {
			t := types.ByEncoding(load.Varint7())
			mutable := load.Varuint1()
			init, _ := readInitExpr(load, m.Module)

			m.globals = append(m.globals, global{t, mutable, init})
		}

		m.data = appendGlobalsData(m.data, m.globals[m.numImportGlobals:])
		m.memoryOffset = len(m.data)
	},

	sectionids.Export: func(m moduleLoader, load loader.L) {
		for i := range load.Count() {
			fieldLen := load.Varuint32()
			if fieldLen > maxStringLen {
				panic(fmt.Errorf("field string is too long in export #%d", i))
			}

			fieldStr := load.Bytes(fieldLen)
			kind := externalKind(load.Byte())
			index := load.Varuint32()

			switch kind {
			case externalKindFunction:
				if fieldLen > 0 && string(fieldStr) == m.EntrySymbol {
					if index >= uint32(len(m.funcSigs)) {
						panic(fmt.Errorf("export function index out of bounds: %d", index))
					}

					sigIndex := m.funcSigs[index]
					sig := m.sigs[sigIndex]
					if len(sig.Args) > 0 || !(sig.Result == types.Void || sig.Result == types.I32) {
						panic(fmt.Errorf("invalid main function signature: %s %s", m.EntrySymbol, sig))
					}

					m.entryIndex = index
					m.entryDefined = true
				}

			case externalKindTable, externalKindMemory, externalKindGlobal:

			default:
				panic(fmt.Errorf("unknown export kind: %s", kind))
			}
		}
	},

	sectionids.Start: func(m moduleLoader, load loader.L) {
		index := load.Varuint32()
		if index >= uint32(len(m.funcSigs)) {
			panic(fmt.Errorf("start function index out of bounds: %d", index))
		}

		sigIndex := m.funcSigs[index]
		sig := m.sigs[sigIndex]
		if len(sig.Args) > 0 || sig.Result != types.Void {
			panic(fmt.Errorf("invalid start function signature: %s", sig))
		}

		m.startIndex = index
		m.startDefined = true
	},

	sectionids.Element: func(m moduleLoader, load loader.L) {
		for i := range load.Count() {
			if index := load.Varuint32(); index != 0 {
				panic(fmt.Errorf("unsupported table index: %d", index))
			}

			offset := readOffsetInitExpr(load, m.Module)

			numElem := load.Varuint32()

			needSize := uint64(offset) + uint64(numElem)
			if needSize > uint64(m.tableLimits.initial) {
				panic(fmt.Errorf("table segment #%d exceeds initial table size", i))
			}

			oldSize := len(m.tableFuncs)
			if needSize > uint64(oldSize) {
				buf := make([]uint32, needSize)
				copy(buf, m.tableFuncs)
				for i := oldSize; i < int(offset); i++ {
					buf[i] = math.MaxInt32 // invalid function index
				}
				m.tableFuncs = buf
			}

			for j := int(offset); j < int(needSize); j++ {
				elem := load.Varuint32()
				if elem >= uint32(len(m.funcSigs)) {
					panic(fmt.Errorf("table element index out of bounds: %d", elem))
				}

				m.tableFuncs[j] = elem
			}
		}
	},

	sectionids.Code: func(m moduleLoader, load loader.L) {
		moduleCoder{m.Module}.genCode(load, m.startTrigger)
	},

	sectionids.Data: func(m moduleLoader, load loader.L) {
		m.genData(load)
	},
}

// LoadCodeSection, after loading the preliminary sections.
func (m *Module) LoadCodeSection(r reader.Reader, textBuf Buffer, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadCodeSection(r, textBuf, roDataBuf, roDataAbsAddr, startTrigger)
	return
}

func (m *Module) loadCodeSection(r reader.Reader, textBuf Buffer, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) {
	if m.funcLinks != nil {
		panic(errors.New("code section has already been loaded"))
	}

	m.text = textBuf
	m.roData.buf = roDataBuf[:0]
	m.roDataAbsAddr = roDataAbsAddr

	load := loader.L{Reader: r}

	if readSectionHeader(load, sectionids.Code, "not a code section") {
		moduleCoder{m}.genCode(load, startTrigger)
	}
}

// LoadDataSection, after loading the preliminary sections.
func (m *Module) LoadDataSection(r reader.Reader) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadDataSection(r)
	return
}

func (m *Module) loadDataSection(r reader.Reader) {
	load := loader.L{Reader: r}

	if readSectionHeader(load, sectionids.Data, "not a data section") {
		m.genData(load)
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

// Signatures are available after preliminary sections have been loaded.
func (m *Module) Signatures() []types.Function {
	return m.sigs
}

// FunctionSignatures are available after preliminary sections have been loaded.
func (m *Module) FunctionSignatures() (funcSigs []types.Function) {
	funcSigs = make([]types.Function, len(m.funcSigs))
	for i, sigIndex := range m.funcSigs {
		funcSigs[i] = m.sigs[sigIndex]
	}
	return
}

// MemoryLimits are available after preliminary sections have been loaded.
func (m *Module) MemoryLimits() (initial, maximum wasm.MemorySize) {
	initial = wasm.MemorySize(m.memoryLimits.initial)
	maximum = wasm.MemorySize(m.memoryLimits.maximum)
	return
}

// Text is available after code section has been loaded.
func (m *Module) Text() (b []byte) {
	if m.text != nil {
		b = m.text.Bytes()
	}
	return
}

// ROData is available after code section has been loaded.
func (m *Module) ROData() []byte {
	return m.roData.buf
}

// FunctionMap is available after code section has been loaded.
func (m *Module) FunctionMap() []byte {
	return m.funcMap.Bytes()
}

// CallMap is available after code section has been loaded.
func (m *Module) CallMap() []byte {
	return m.callMap.Bytes()
}

// Data is available after data section has been loaded.
func (m *Module) Data() (data []byte, memoryOffset int) {
	data = m.data
	memoryOffset = m.memoryOffset
	return
}
