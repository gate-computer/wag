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
	"github.com/tsavola/wag/internal/section"
	"github.com/tsavola/wag/internal/typedecode"
	"github.com/tsavola/wag/wa"
)

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader = reader.R

type CodeBuffer = code.Buffer
type DataBuffer = data.Buffer

const (
	maxStringLen          = 255   // TODO
	maxTableLimit         = 32768 // TODO
	maxInitialMemoryLimit = 16384 // TODO
	maxMaximumMemoryLimit = math.MaxInt32 >> wa.PageBits
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

	m.MemoryLimitValues = readResizableLimits(load, maxInitialMemoryLimit, maxMaximumMemoryLimit, wa.PageSize)
}

// Config for loading WebAssembly module sections.
type Config struct {
	UnknownSectionLoader func(r Reader, payloadLen uint32) error
}

// ModuleConfig for a single compiler invocation.
type ModuleConfig struct {
	Config
}

// Module contains a WebAssembly module specification without code or data.
type Module struct {
	m module.M
}

// LoadInitialSections reads module header and all sections preceding code and
// data.
func LoadInitialSections(config *ModuleConfig, r Reader) (m *Module, err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	m = loadInitialSections(config, r)
	return
}

func loadInitialSections(config *ModuleConfig, r Reader) (m *Module) {
	m = new(Module)
	load := loader.L{R: r}

	var header module.Header
	if err := binary.Read(load.R, binary.LittleEndian, &header); err != nil {
		panic(err)
	}
	if header.MagicNumber != module.MagicNumber {
		panic(errors.New("not a WebAssembly module"))
	}
	if header.Version != module.Version {
		panic(fmt.Errorf("unsupported module version: %d", header.Version))
	}

	var seenId module.SectionId

	for {
		value, err := load.R.ReadByte()
		if err != nil {
			if err == io.EOF {
				return
			}
			panic(err)
		}

		id := module.SectionId(value)

		if id != module.SectionUnknown {
			if id <= seenId {
				panic(fmt.Errorf("section 0x%x follows section 0x%x", id, seenId))
			}
			seenId = id
		}

		if id >= module.NumMetaSections {
			load.R.UnreadByte()
			if id >= module.NumSections {
				panic(fmt.Errorf("unknown section id: 0x%x", id))
			}
			return
		}

		payloadLen := load.Varuint32()
		metaSectionLoaders[id](m, config, payloadLen, load)
	}
}

var metaSectionLoaders = [module.NumMetaSections]func(*Module, *ModuleConfig, uint32, loader.L){
	module.SectionUnknown: func(m *Module, config *ModuleConfig, payloadLen uint32, load loader.L) {
		var err error
		if config.UnknownSectionLoader != nil {
			err = config.UnknownSectionLoader(load.R, payloadLen)
		} else {
			_, err = io.CopyN(ioutil.Discard, load.R, int64(payloadLen))
		}
		if err != nil {
			panic(err)
		}
	},

	module.SectionType: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
		for i := range load.Count() {
			if form := load.Varint7(); form != -0x20 {
				panic(fmt.Errorf("unsupported function type form: %d", form))
			}

			var sig wa.FuncType

			paramCount := load.Varuint32()
			if paramCount > codegen.MaxFuncParams {
				panic(fmt.Errorf("function type #%d has too many parameters: %d", i, paramCount))
			}

			sig.Params = make([]wa.Type, paramCount)
			for j := range sig.Params {
				sig.Params[j] = typedecode.Value(load.Varint7())
			}

			if returnCount1 := load.Varuint1(); returnCount1 {
				sig.Result = typedecode.Value(load.Varint7())
			}

			m.m.Types = append(m.m.Types, sig)
		}
	},

	module.SectionImport: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
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
				if sigIndex >= uint32(len(m.m.Types)) {
					panic(fmt.Errorf("function type index out of bounds in import #%d: 0x%x", i, sigIndex))
				}

				m.m.Funcs = append(m.m.Funcs, sigIndex)

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

	module.SectionFunction: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
		for range load.Count() {
			sigIndex := load.Varuint32()
			if sigIndex >= uint32(len(m.m.Types)) {
				panic(fmt.Errorf("function type index out of bounds: %d", sigIndex))
			}

			m.m.Funcs = append(m.m.Funcs, sigIndex)
		}
	},

	module.SectionTable: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
		for range load.Count() {
			readTable(&m.m, load)
		}
	},

	module.SectionMemory: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
		for range load.Count() {
			readMemory(&m.m, load)
		}
	},

	module.SectionGlobal: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
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

	module.SectionExport: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
		m.m.ExportFuncs = make(map[string]uint32)

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
				if index >= uint32(len(m.m.Funcs)) {
					panic(fmt.Errorf("export function index out of bounds: %d", index))
				}
				m.m.ExportFuncs[string(fieldStr)] = index

			case module.ExternalKindTable, module.ExternalKindMemory, module.ExternalKindGlobal:

			default:
				panic(fmt.Errorf("unknown export kind: %s", kind))
			}
		}
	},

	module.SectionStart: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
		index := load.Varuint32()
		if index >= uint32(len(m.m.Funcs)) {
			panic(fmt.Errorf("start function index out of bounds: %d", index))
		}

		sigIndex := m.m.Funcs[index]
		sig := m.m.Types[sigIndex]
		if len(sig.Params) > 0 || sig.Result != wa.Void {
			panic(fmt.Errorf("invalid start function signature: %s", sig))
		}

		m.m.StartIndex = index
		m.m.StartDefined = true
	},

	module.SectionElement: func(m *Module, _ *ModuleConfig, _ uint32, load loader.L) {
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
				if elem >= uint32(len(m.m.Funcs)) {
					panic(fmt.Errorf("table element index out of bounds: %d", elem))
				}

				m.m.TableFuncs[j] = elem
			}
		}
	},
}

func (m *Module) Types() []wa.FuncType { return m.m.Types }

func (m *Module) FuncTypes() []wa.FuncType {
	sigs := make([]wa.FuncType, len(m.m.Funcs))
	for i, sigIndex := range m.m.Funcs {
		sigs[i] = m.m.Types[sigIndex]
	}
	return sigs
}

func (m *Module) InitialMemorySize() int { return m.m.MemoryLimitValues.Initial }
func (m *Module) MemorySizeLimit() int   { return m.m.MemoryLimitValues.Maximum }

func (m *Module) NumImportFuncs() int   { return len(m.m.ImportFuncs) }
func (m *Module) NumImportGlobals() int { return len(m.m.ImportGlobals) }

func (m *Module) ImportFunc(i int) (module, field string, sig wa.FuncType) {
	imp := m.m.ImportFuncs[i]
	module = imp.Module
	field = imp.Field

	sigIndex := m.m.Funcs[i]
	sig = m.m.Types[sigIndex]
	return
}

func (m *Module) ImportGlobal(i int) (module, field string, t wa.Type) {
	imp := m.m.ImportGlobals[i]
	module = imp.Module
	field = imp.Field

	t = m.m.Globals[i].Type
	return
}

func (m *Module) SetImportFunc(i int, vecIndex int)  { m.m.ImportFuncs[i].VecIndex = vecIndex }
func (m *Module) SetImportGlobal(i int, init uint64) { m.m.Globals[i].Init = init }

func (m *Module) GlobalsSize() int {
	size := len(m.m.Globals) * obj.Word
	mask := datalayout.MinAlignment - 1 // Round up so that linear memory will
	return (size + mask) &^ mask        // have at least minimum alignment.
}

func (m *Module) ExportFuncs() map[string]uint32 { return m.m.ExportFuncs }

func (m *Module) ExportFunc(field string) (funcIndex uint32, sig wa.FuncType, found bool) {
	funcIndex, found = m.m.ExportFuncs[field]
	if found {
		sigIndex := m.m.Funcs[funcIndex]
		sig = m.m.Types[sigIndex]
	}
	return
}

// CodeConfig for a single compiler invocation.
type CodeConfig struct {
	Text         CodeBuffer // Initialized with default implementation if nil.
	Map          ObjectMapper
	EventHandler func(event.Event)
	LastInitFunc uint32
	Config
}

// LoadCodeSection reads a WebAssembly module's code section and generates
// machine code.
func LoadCodeSection(config *CodeConfig, r Reader, mod *Module) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	loadCodeSection(config, r, mod)
	return
}

func loadCodeSection(config *CodeConfig, r Reader, mod *Module) {
	if config.Text == nil {
		config.Text = new(defaultBuffer)
	}

	objMap := config.Map
	if objMap == nil {
		objMap = dummyMap{}
	}

	load := loader.L{R: r}

	switch id := section.Find(module.SectionCode, load, config.UnknownSectionLoader); id {
	case module.SectionCode:
		load.Varuint32() // payload len
		codegen.GenProgram(config.Text, objMap, load, &mod.m, config.EventHandler, int(config.LastInitFunc)+1)

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
	GlobalsMemory   DataBuffer // Initialized with default implementation if nil.
	MemoryAlignment int        // Initialized with minimal value if zero.
	Config
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

	switch id := section.Find(module.SectionData, load, config.UnknownSectionLoader); id {
	case module.SectionData:
		load.Varuint32() // payload len
		datalayout.ReadMemory(config.GlobalsMemory, load, &mod.m)

	case 0:
		// no sections

	default:
		panic(fmt.Errorf("unexpected section id: 0x%x (looking for data section)", id))
	}
}

// LoadUnknownSections reads a WebAssembly module's extension sections which
// follow known sections.
func LoadUnknownSections(config *Config, r Reader) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	loadUnknownSections(config, r)
	return
}

func loadUnknownSections(config *Config, r Reader) {
	load := loader.L{R: r}

	if id := section.Find(0, load, config.UnknownSectionLoader); id != 0 {
		panic(fmt.Errorf("unexpected section id: 0x%x (after all known sections)", id))
	}
}
