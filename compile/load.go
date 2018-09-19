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
	"github.com/tsavola/wag/compile/event"
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/data"
	"github.com/tsavola/wag/internal/datalayout"
	"github.com/tsavola/wag/internal/errorpanic"
	"github.com/tsavola/wag/internal/gen/codegen"
	"github.com/tsavola/wag/internal/initexpr"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/internal/reader"
	"github.com/tsavola/wag/internal/typedecode"
	"github.com/tsavola/wag/wasm"
)

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader = reader.R

type CodeBuffer = code.Buffer
type DataBuffer = data.Buffer

// ImportResolver maps symbols to function addresses and constant values.
type ImportResolver interface {
	ResolveFunc(module, field string, sig abi.Sig) (addr uint64, err error)
	ResolveGlobal(module, field string, t abi.Type) (init uint64, err error)
}

type variadicImportResolver interface {
	ImportResolver
	ResolveVariadicFunc(module, field string, sig abi.Sig) (variadic bool, addr uint64, err error)
}

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

// Module contains a WebAssembly module's metadata.
type Module struct {
	EntrySymbol          string   // Used to resolve the entry function during
	EntryArgs            []uint64 // initial section loading.
	UnknownSectionLoader func(r Reader, payloadLen uint32) error

	m module.M
}

// LoadInitialSections reads all sections preceding code and data, initializing
// the Module instance.
func (m *Module) LoadInitialSections(r Reader) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	m.loadInitialSections(r)
	return
}

func (m *Module) loadInitialSections(r Reader) {
	load := loader.L{R: r}

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

	var seenId byte

	for {
		id, err := load.ReadByte()
		if err != nil {
			if err == io.EOF {
				return
			}
			panic(err)
		}

		if id != module.SectionUnknown {
			if id <= seenId {
				panic(fmt.Errorf("section 0x%x follows section 0x%x", id, seenId))
			}
			seenId = id
		}

		if id >= module.NumMetaSections {
			load.UnreadByte()
			if id >= module.NumSections {
				panic(fmt.Errorf("unknown section id: 0x%x", id))
			}
			return
		}

		payloadLen := load.Varuint32()
		metaSectionLoaders[id](payloadLen, m, load)
	}
}

var metaSectionLoaders = [module.NumMetaSections]func(uint32, *Module, loader.L){
	module.SectionUnknown: func(payloadLen uint32, m *Module, load loader.L) {
		var err error
		if m.UnknownSectionLoader != nil {
			err = m.UnknownSectionLoader(load, payloadLen)
		} else {
			_, err = io.CopyN(ioutil.Discard, load, int64(payloadLen))
		}
		if err != nil {
			panic(err)
		}
	},

	module.SectionType: func(_ uint32, m *Module, load loader.L) {
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

	module.SectionImport: func(_ uint32, m *Module, load loader.L) {
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

				m.m.FuncSigs = append(m.m.FuncSigs, sigIndex)

				m.m.ImportFuncs = append(m.m.ImportFuncs, module.ImportFunc{
					Import: module.Import{
						Module: moduleStr,
						Field:  fieldStr,
					},
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

				if mutable := load.Varuint1(); mutable {
					panic(fmt.Errorf("unsupported mutable global in import #%d", i))
				}

				m.m.Globals = append(m.m.Globals, module.Global{
					Type: t,
				})

				m.m.ImportGlobals = append(m.m.ImportGlobals, module.Import{
					Module: moduleStr,
					Field:  fieldStr,
				})

			default:
				panic(fmt.Errorf("import kind not supported: %s", kind))
			}
		}
	},

	module.SectionFunction: func(_ uint32, m *Module, load loader.L) {
		for range load.Count() {
			sigIndex := load.Varuint32()
			if sigIndex >= uint32(len(m.m.Sigs)) {
				panic(fmt.Errorf("function type index out of bounds: %d", sigIndex))
			}

			m.m.FuncSigs = append(m.m.FuncSigs, sigIndex)
		}
	},

	module.SectionTable: func(_ uint32, m *Module, load loader.L) {
		for range load.Count() {
			readTable(&m.m, load)
		}
	},

	module.SectionMemory: func(_ uint32, m *Module, load loader.L) {
		for range load.Count() {
			readMemory(&m.m, load)
		}
	},

	module.SectionGlobal: func(_ uint32, m *Module, load loader.L) {
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

	module.SectionExport: func(_ uint32, m *Module, load loader.L) {
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
					if len(sig.Args) > codegen.MaxFuncParams || len(m.EntryArgs) < len(sig.Args) || !(sig.Result == abi.Void || sig.Result == abi.I32) {
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

	module.SectionStart: func(_ uint32, m *Module, load loader.L) {
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

	module.SectionElement: func(_ uint32, m *Module, load loader.L) {
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
}

func (m *Module) Sigs() []abi.Sig {
	return m.m.Sigs
}

func (m *Module) FuncSigs() (funcSigs []abi.Sig) {
	funcSigs = make([]abi.Sig, len(m.m.FuncSigs))
	for i, sigIndex := range m.m.FuncSigs {
		funcSigs[i] = m.m.Sigs[sigIndex]
	}
	return
}

func (m *Module) MemoryLimits() (initial, maximum wasm.MemorySize) {
	initial = wasm.MemorySize(m.m.MemoryLimitValues.Initial)
	maximum = wasm.MemorySize(m.m.MemoryLimitValues.Maximum)
	return
}

func (m *Module) NumImportFunc() int   { return len(m.m.ImportFuncs) }
func (m *Module) NumImportGlobal() int { return len(m.m.ImportGlobals) }

func (m *Module) ImportFunc(i int) (module, field string, sig abi.Sig) {
	imp := m.m.ImportFuncs[i]
	module = imp.Module
	field = imp.Field

	sigIndex := m.m.FuncSigs[i]
	sig = m.m.Sigs[sigIndex]
	return
}

func (m *Module) ImportGlobal(i int) (module, field string, t abi.Type) {
	imp := m.m.ImportGlobals[i]
	module = imp.Module
	field = imp.Field

	t = m.m.Globals[i].Type
	return
}

func (m *Module) DefineImportFunc(i int, addr uint64)   { m.m.ImportFuncs[i].Addr = addr }
func (m *Module) DefineImportGlobal(i int, init uint64) { m.m.Globals[i].Init = init }

func (m *Module) DefineImports(res ImportResolver) (err error) {
	if varRes, ok := res.(variadicImportResolver); ok {
		for i := range m.m.ImportFuncs {
			imp := &m.m.ImportFuncs[i]
			imp.Variadic, imp.Addr, err = varRes.ResolveVariadicFunc(m.ImportFunc(i))
			if err != nil {
				return
			}
		}
	} else {
		for i := range m.m.ImportFuncs {
			m.m.ImportFuncs[i].Addr, err = res.ResolveFunc(m.ImportFunc(i))
			if err != nil {
				return
			}
		}
	}

	for i := range m.m.ImportGlobals {
		m.m.Globals[i].Init, err = res.ResolveGlobal(m.ImportGlobal(i))
		if err != nil {
			return
		}
	}

	return
}

func (m *Module) defineImports(res ImportResolver) {
	if err := m.DefineImports(res); err != nil {
		panic(err)
	}
}

func (m *Module) GlobalsSize() int {
	size := len(m.m.Globals) * obj.Word
	mask := datalayout.MinAlignment - 1 // Round up so that linear memory will
	return (size + mask) &^ mask        // have at least minimum alignment.
}

// CopyGlobalsData copies globals' initial values into dest, aligning them
// against its end.  len(dest) must be at least m.GlobalsSize().
func (m *Module) CopyGlobalsData(dest []byte) {
	datalayout.CopyGlobalsAtEnd(dest, &m.m)
}

// CodeConfig for a single compiler invocation.
type CodeConfig struct {
	Text                 CodeBuffer // Initialized with default implementation if nil.
	ROData               DataBuffer // Initialized with default implementation if nil.
	RODataAddr           uintptr
	ObjectMapper         ObjectMap
	EventHandler         func(event.Event)
	UnknownSectionLoader func(r Reader, payloadLen uint32) error
}

// LoadCodeSection reads a WebAssembly module's code section and generates
// machine code and read-only data.
func LoadCodeSection(config *CodeConfig, r Reader, mod *Module) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	loadCodeSection(config, r, mod)
	return
}

func loadCodeSection(config *CodeConfig, r Reader, mod *Module) {
	if mod.EntrySymbol != "" && !mod.m.EntryDefined {
		panic(fmt.Errorf("%s function not found in export section", mod.EntrySymbol))
	}

	if config.Text == nil {
		config.Text = new(defaultBuffer)
	}
	if config.ROData == nil {
		config.ROData = new(defaultBuffer)
	}

	objMap := config.ObjectMapper
	if objMap == nil {
		objMap = dummyMap{}
	}

	load := loader.L{R: r}

	switch id := findSection(module.SectionCode, load, config.UnknownSectionLoader); id {
	case module.SectionCode:
		codegen.GenProgram(config.Text, config.ROData, int32(config.RODataAddr), objMap, load, &mod.m, mod.EntrySymbol, mod.EntryArgs, config.EventHandler)

	case module.SectionData:
		// no code section

	case 0:
		// no sections

	default:
		panic(fmt.Errorf("unexpected section id: 0x%x (looking for code section)", id))
	}
}

// DataConfig for a single compiler invocation.
type DataConfig struct {
	GlobalsMemory        DataBuffer // Initialized with default implementation if nil.
	MemoryAlignment      int        // Initialized with minimal value if zero.
	UnknownSectionLoader func(r Reader, payloadLen uint32) error
}

// LoadDataSection reads a WebAssembly module's data section and generates
// initial contents of mutable program state (globals and linear memory).
func LoadDataSection(config *DataConfig, r Reader, mod *Module) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	loadDataSection(config, r, mod)
	return
}

func loadDataSection(config *DataConfig, r Reader, mod *Module) {
	if config.GlobalsMemory == nil {
		config.GlobalsMemory = new(defaultBuffer)
	}
	if config.MemoryAlignment == 0 {
		config.MemoryAlignment = datalayout.MinAlignment
	}

	datalayout.CopyGlobalsAlign(config.GlobalsMemory, &mod.m, config.MemoryAlignment)

	load := loader.L{R: r}

	switch id := findSection(module.SectionData, load, config.UnknownSectionLoader); id {
	case module.SectionData:
		datalayout.ReadMemory(config.GlobalsMemory, load, &mod.m)

	case 0:
		// no sections

	default:
		panic(fmt.Errorf("unexpected section id: 0x%x (looking for data section)", id))
	}
}

// LoadUnknownSections reads a WebAssembly module's extension sections which
// follow known sections.
func LoadUnknownSections(unknownLoader func(r Reader, payloadLen uint32) error, r Reader) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	loadUnknownSections(unknownLoader, r)
	return
}

func loadUnknownSections(unknownLoader func(Reader, uint32) error, r Reader) {
	load := loader.L{R: r}

	if id := findSection(0, load, unknownLoader); id != 0 {
		panic(fmt.Errorf("unexpected section id: 0x%x (after all known sections)", id))
	}
}

func findSection(findId byte, load loader.L, unknownLoader func(Reader, uint32) error) byte {
	for {
		id, err := load.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0
			}
			panic(err)
		}

		switch id {
		case module.SectionUnknown: // = 0
			payloadLen := load.Varuint32()

			if unknownLoader != nil {
				err = unknownLoader(load, payloadLen)
			} else {
				_, err = io.CopyN(ioutil.Discard, load, int64(payloadLen))
			}
			if err != nil {
				panic(err)
			}

		case findId:
			load.Varuint32() // payloadLen
			return id

		default:
			load.UnreadByte()
			return id
		}
	}
}
