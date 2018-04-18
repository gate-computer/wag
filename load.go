// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"

	"github.com/tsavola/wag/internal/errutil"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/types"
	"github.com/tsavola/wag/wasm"
)

type Environment interface {
	ImportFunction(module, field string, sig types.Function) (variadic bool, absAddr uint64, err error)
	ImportGlobal(module, field string, t types.T) (valueBits uint64, err error)
}

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader = module.Reader

type Buffer = module.Buffer

type InsnMap interface {
	Init(numFuncs int)
	PutFunc(pos int32)
	PutInsn(pos int32)
}

const (
	maxStringLen          = 255 // TODO
	maxImportParams       = gen.StackReserve/gen.WordSize - 2
	maxFunctionParams     = 255   // index+1 must fit in uint8
	maxFunctionVars       = 8191  // index must fit in uint16; TODO
	maxTableLimit         = 32768 // TODO
	maxInitialMemoryLimit = 256   // TODO
	maxMaximumMemoryLimit = math.MaxInt32 >> wasm.PageBits
	maxEntryParams        = 8     // param registers on x86-64
	maxBranchTableSize    = 32768 // TODO
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
	UnknownSectionLoader func(r Reader, payloadLen uint32) error
	InsnMap              InsnMap

	module.Internal
}

// LoadPreliminarySections, excluding the code and data sections.
func (m *Module) LoadPreliminarySections(r Reader, env Environment) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadPreliminarySections(r, env)
	return
}

func (m *Module) loadPreliminarySections(r Reader, env Environment) {
	moduleLoader{m, env, nil}.loadUntil(loader.L{Reader: r}, module.SectionCode)
}

// Load all (remaining) sections.
func (m *Module) Load(r Reader, env Environment, textBuffer Buffer, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.load(r, env, textBuffer, roDataBuf, roDataAbsAddr, startTrigger)
	return
}

func (m *Module) load(r Reader, env Environment, textBuffer Buffer, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) {
	m.TextBuffer = textBuffer
	m.RODataBuf = roDataBuf[:0]
	m.RODataAbsAddr = roDataAbsAddr

	moduleLoader{m, env, startTrigger}.load(loader.L{Reader: r})
}

type moduleLoader struct {
	*Module
	env          Environment
	startTrigger chan<- struct{}
}

func (m moduleLoader) load(load loader.L) {
	nextId := m.loadUntil(load, module.NumSections)
	if nextId != 0 {
		panic(fmt.Errorf("unknown section id: 0x%x", nextId))
	}
}

func (m moduleLoader) loadUntil(load loader.L, untilSection byte) byte {
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
			f(m, load)
		} else if err := skipSection(id, payloadLen); err != nil {
			panic(err)
		}
	}
}

var sectionLoaders = []func(moduleLoader, loader.L){
	module.SectionType: func(m moduleLoader, load loader.L) {
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

			m.Sigs = append(m.Sigs, sig)
		}
	},

	module.SectionImport: func(m moduleLoader, load loader.L) {
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
				if sigIndex >= uint32(len(m.Sigs)) {
					panic(fmt.Errorf("function type index out of bounds in import #%d: 0x%x", i, sigIndex))
				}

				sig := m.Sigs[sigIndex]
				if n := len(sig.Args); n > maxImportParams {
					panic(fmt.Errorf("import function #%d has too many parameters: %d", i, n))
				}

				funcIndex := len(m.FuncSigs)
				m.FuncSigs = append(m.FuncSigs, sigIndex)

				variadic, absAddr, err := m.env.ImportFunction(moduleStr, fieldStr, sig)
				if err != nil {
					panic(err)
				}

				m.ImportFuncs = append(m.ImportFuncs, module.ImportFunction{
					FuncIndex: funcIndex,
					Variadic:  variadic,
					AbsAddr:   absAddr,
				})

			case module.ExternalKindGlobal:
				t := types.ByEncoding(load.Varint7())

				mutable := load.Varuint1()
				if mutable {
					panic(fmt.Errorf("unsupported mutable global in import #%d", i))
				}

				init, err := m.env.ImportGlobal(moduleStr, fieldStr, t)
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

		m.DataBuf = appendGlobalsData(m.DataBuf, m.Globals)
		m.MemoryOffset = len(m.DataBuf)
	},

	module.SectionFunction: func(m moduleLoader, load loader.L) {
		for range load.Count() {
			sigIndex := load.Varuint32()
			if sigIndex >= uint32(len(m.Sigs)) {
				panic(fmt.Errorf("function type index out of bounds: %d", sigIndex))
			}

			m.FuncSigs = append(m.FuncSigs, sigIndex)
		}
	},

	module.SectionTable: func(m moduleLoader, load loader.L) {
		for range load.Count() {
			if m.TableLimitValues.Defined {
				panic(errors.New("multiple tables not supported"))
			}

			if elementType := load.Varint7(); elementType != -0x10 {
				panic(fmt.Errorf("unsupported table element type: %d", elementType))
			}

			m.TableLimitValues = readResizableLimits(load, maxTableLimit, maxTableLimit, 1)
		}
	},

	module.SectionMemory: func(m moduleLoader, load loader.L) {
		for range load.Count() {
			if m.MemoryLimitValues.Defined {
				panic(errors.New("multiple memories not supported"))
			}

			m.MemoryLimitValues = readResizableLimits(load, maxInitialMemoryLimit, maxMaximumMemoryLimit, int(wasm.Page))
		}
	},

	module.SectionGlobal: func(m moduleLoader, load loader.L) {
		// TODO: limit number of globals
		for range load.Count() {
			t := types.ByEncoding(load.Varint7())
			mutable := load.Varuint1()
			init, _ := readInitExpr(load, m.Module)

			m.Globals = append(m.Globals, module.Global{
				Type:    t,
				Mutable: mutable,
				Init:    init,
			})
		}

		m.DataBuf = appendGlobalsData(m.DataBuf, m.Globals[m.NumImportGlobals:])
		m.MemoryOffset = len(m.DataBuf)
	},

	module.SectionExport: func(m moduleLoader, load loader.L) {
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
					if index >= uint32(len(m.FuncSigs)) {
						panic(fmt.Errorf("export function index out of bounds: %d", index))
					}

					sigIndex := m.FuncSigs[index]
					sig := m.Sigs[sigIndex]
					if len(sig.Args) > maxEntryParams || len(m.EntryArgs) < len(sig.Args) || !(sig.Result == types.Void || sig.Result == types.I32) {
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

	module.SectionStart: func(m moduleLoader, load loader.L) {
		index := load.Varuint32()
		if index >= uint32(len(m.FuncSigs)) {
			panic(fmt.Errorf("start function index out of bounds: %d", index))
		}

		sigIndex := m.FuncSigs[index]
		sig := m.Sigs[sigIndex]
		if len(sig.Args) > 0 || sig.Result != types.Void {
			panic(fmt.Errorf("invalid start function signature: %s", sig))
		}

		m.StartIndex = index
		m.StartDefined = true
	},

	module.SectionElement: func(m moduleLoader, load loader.L) {
		for i := range load.Count() {
			if index := load.Varuint32(); index != 0 {
				panic(fmt.Errorf("unsupported table index: %d", index))
			}

			offset := readOffsetInitExpr(load, m.Module)

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
				if elem >= uint32(len(m.FuncSigs)) {
					panic(fmt.Errorf("table element index out of bounds: %d", elem))
				}

				m.TableFuncs[j] = elem
			}
		}
	},

	module.SectionCode: func(m moduleLoader, load loader.L) {
		moduleCoder{m.Module}.genCode(load, m.startTrigger)
	},

	module.SectionData: func(m moduleLoader, load loader.L) {
		m.genData(load)
	},
}

// LoadCodeSection, after loading the preliminary sections.
func (m *Module) LoadCodeSection(r Reader, textBuffer Buffer, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadCodeSection(r, textBuffer, roDataBuf, roDataAbsAddr, startTrigger)
	return
}

func (m *Module) loadCodeSection(r Reader, textBuffer Buffer, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) {
	if m.FuncLinks != nil {
		panic(errors.New("code section has already been loaded"))
	}

	m.TextBuffer = textBuffer
	m.RODataBuf = roDataBuf[:0]
	m.RODataAbsAddr = roDataAbsAddr

	load := loader.L{Reader: r}

	if readSectionHeader(load, module.SectionCode, "not a code section") {
		moduleCoder{m}.genCode(load, startTrigger)
	}
}

// LoadDataSection, after loading the preliminary sections.
func (m *Module) LoadDataSection(r Reader) (err error) {
	defer func() {
		err = errutil.ErrorOrPanic(recover())
	}()

	m.loadDataSection(r)
	return
}

func (m *Module) loadDataSection(r Reader) {
	load := loader.L{Reader: r}

	if readSectionHeader(load, module.SectionData, "not a data section") {
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
	return m.Sigs
}

// FunctionSignatures are available after preliminary sections have been loaded.
func (m *Module) FunctionSignatures() (funcSigs []types.Function) {
	funcSigs = make([]types.Function, len(m.FuncSigs))
	for i, sigIndex := range m.FuncSigs {
		funcSigs[i] = m.Sigs[sigIndex]
	}
	return
}

// MemoryLimits are available after preliminary sections have been loaded.
func (m *Module) MemoryLimits() (initial, maximum wasm.MemorySize) {
	initial = wasm.MemorySize(m.MemoryLimitValues.Initial)
	maximum = wasm.MemorySize(m.MemoryLimitValues.Maximum)
	return
}

// Text is available after code section has been loaded.
func (m *Module) Text() (b []byte) {
	if m.TextBuffer != nil {
		b = m.TextBuffer.Bytes()
	}
	return
}

// ROData is available after code section has been loaded.
func (m *Module) ROData() []byte {
	return m.RODataBuf
}

// FunctionMap is available after code section has been loaded.
func (m *Module) FunctionMap() []byte {
	return m.FuncMapBuffer.Bytes()
}

// CallMap is available after code section has been loaded.
func (m *Module) CallMap() []byte {
	return m.CallMapBuffer.Bytes()
}

// Data is available after data section has been loaded.
func (m *Module) Data() (data []byte, memoryOffset int) {
	data = m.DataBuf
	memoryOffset = m.MemoryOffset
	return
}
