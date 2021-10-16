// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package compile implements a WebAssembly compiler.


Text

Module sections (wasm v1) which affect the immutable text (machine code):

	Type
	Import
	Function
	Table
	Memory (*)
	Global (*)
	Element
	Code

(*) Memory sizes and global values do not affect text, only their counts and
types do.

Sections which have no effect on text:

	Export
	Start
	Data
	Custom sections

Vector-based import function indexes also affect text, but their addresses are
configured at run-time by mapping the vector immediately before text.


Globals and memory

The memory, global and data sections comprise a single mutable buffer.


Stack

Any effect the export and start sections have happens via the run-time stack
buffer, which must be initialized with optional start and entry function
addresses.

Stack regions from low to high address:

	1. Space for runtime-specific variables.
	2. Space for signal stacks and red zones.
	3. 240 bytes for use by trap handlers and vector-based import functions.
	4. 8 bytes for trap handler return address (included in call stack).
	5. 8 bytes for an extra function call (included in call stack).
	6. The rest of the call stack (size must be a multiple of 8).
	7. Start function address (4 bytes padded to 8).
	8. Entry function address (4 bytes padded to 8).

Address of region 3 must be aligned so that the threshold between regions 5 and
6 (the stack limit) is a multiple of 256.

Function addresses are relative to the start of text.  Zero address causes the
function to be skipped.

Stack pointer is initially positioned between regions 6 and 7.  Function
prologue compares the stack pointer against the threshold between regions 5 and
6 (the stack limit).

*/
package compile

import (
	"bytes"
	encodingbinary "encoding/binary"
	"io"
	"io/ioutil"
	"math"

	"gate.computer/wag/binary"
	"gate.computer/wag/buffer"
	"gate.computer/wag/compile/event"
	"gate.computer/wag/internal/code"
	"gate.computer/wag/internal/data"
	"gate.computer/wag/internal/datalayout"
	"gate.computer/wag/internal/errorpanic"
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/codegen"
	"gate.computer/wag/internal/initexpr"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/internal/section"
	"gate.computer/wag/internal/typedecode"
	"gate.computer/wag/wa"
)

// Some limits have been chosen based on the backends' limitations:
//
// - MaxTextSize is the range supported by ARM64 branch instructions.
//
// - maxGlobals * -obj.Word is the smallest offset which can be encoded in an
//   ARM64 load instruction.
//
// - All limits are small enough to keep values below 2^31, so that simple
//   signed 32-bit comparisons can be used by the x86 backend.
//
// (More limits are defined in codegen package.)

const (
	MaxTextSize   = 512 * 1024 * 1024
	MaxMemorySize = maxMemoryPages * wa.PageSize

	defaultTextBufferSize   = 32768
	defaultMemoryBufferSize = 32768

	maxStringSize     = 100000   // Industry standard.
	maxTableLen       = 10000000 // Industry standard.
	maxMemoryPages    = 32767    // Industry standard.
	maxGlobals        = 32
	defaultMaxExports = 64
	maxElements       = 10000000 // Industry standard.
)

var emptyCodeSectionPayload = []byte{
	0, // function count
}

// Reader is a subset of bufio.Reader, bytes.Buffer and bytes.Reader.
type Reader = binary.Reader

type CodeBuffer = code.Buffer
type DataBuffer = data.Buffer

type ObjectMapper = obj.ObjectMapper
type DebugObjectMapper = obj.DebugObjectMapper

type Breakpoint = gen.Breakpoint

func readResizableLimits(load *loader.L, maxInit, maxMax, maxValid uint32, scale int, kind string) module.ResizableLimits {
	maxFieldIsPresent := load.Varuint1()

	init := load.Varuint32()
	if maxValid > 0 && init > maxValid {
		panic(module.Errorf("invalid initial %s size: %d pages", kind, init))
	}
	if init > maxInit {
		panic(module.Errorf("initial %s size is too large: %d", kind, init))
	}

	limits := module.ResizableLimits{
		Init: int(init) * scale,
		Max:  -1,
	}

	if maxFieldIsPresent {
		max := load.Varuint32()
		if maxValid > 0 && max > maxValid {
			panic(module.Errorf("invalid maximum %s size: %d pages", kind, max))
		}
		if max > maxMax {
			max = maxMax
		}
		if max < init {
			panic(module.Errorf("maximum %s size %d is smaller than initial %s size %d", kind, max, kind, init))
		}
		limits.Max = int(max) * scale
	}

	return limits
}

// Config for loading WebAssembly module sections.
type Config struct {
	// SectionMapper is invoked for every section (standard or custom), just
	// after the section id byte.  It must read and return the payload length
	// (varuint32), but not the payload itself.
	SectionMapper func(sectionID byte, r Reader) (payloadLen uint32, err error)

	// CustomSectionLoader is invoked for every custom section.  It must read
	// exactly payloadLen bytes, or return an error.  SectionMapper (if
	// configured) has been invoked just before it.
	CustomSectionLoader func(r Reader, payloadLen uint32) error
}

// ModuleConfig for a single compiler invocation.
type ModuleConfig struct {
	MaxExports int
	Config
}

// Module contains a WebAssembly module specification without code or data.
type Module struct {
	m module.M
}

// LoadInitialSections reads module header and all sections preceding code and
// data.
func LoadInitialSections(config *ModuleConfig, r Reader) (m Module, err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	m = loadInitialSections(config, r)
	return
}

func loadInitialSections(config *ModuleConfig, r Reader) (m Module) {
	if config == nil {
		config = new(ModuleConfig)
	}
	if config.MaxExports > math.MaxInt32 {
		panic("ModuleConfig.MaxExports is too large")
	} else if config.MaxExports == 0 {
		config.MaxExports = defaultMaxExports
	}

	load := loader.New(r)

	var header module.Header
	if err := encodingbinary.Read(load, encodingbinary.LittleEndian, &header); err != nil {
		panic(err)
	}
	if header.MagicNumber != module.MagicNumber {
		panic(module.Error("not a WebAssembly module"))
	}
	if header.Version != module.Version {
		panic(module.Errorf("unsupported module version: %d", header.Version))
	}

	var seenID module.SectionID

	for {
		sectionID, err := load.ReadByte()
		if err != nil {
			if err == io.EOF {
				return
			}
			panic(err)
		}

		id := module.SectionID(sectionID)

		if id != module.SectionCustom {
			if id <= seenID {
				panic(module.Errorf("section 0x%x follows section 0x%x", id, seenID))
			}
			seenID = id
		}

		if id > module.SectionElement {
			load.UnreadByte()
			if id >= module.NumSections {
				panic(module.Errorf("custom section id: 0x%x", id))
			}
			return
		}

		var payloadLen uint32

		if config.SectionMapper != nil {
			payloadLen, err = config.SectionMapper(sectionID, load)
			if err != nil {
				panic(err)
			}
		} else {
			payloadLen = load.Varuint32()
		}

		initialSectionLoaders[id](&m, config, payloadLen, load)
	}
}

var initialSectionLoaders = [module.SectionElement + 1]func(*Module, *ModuleConfig, uint32, *loader.L){
	module.SectionCustom:   loadCustomSection,
	module.SectionType:     loadTypeSection,
	module.SectionImport:   loadImportSection,
	module.SectionFunction: loadFunctionSection,
	module.SectionTable:    loadTableSection,
	module.SectionMemory:   loadMemorySection,
	module.SectionGlobal:   loadGlobalSection,
	module.SectionExport:   loadExportSection,
	module.SectionStart:    loadStartSection,
	module.SectionElement:  loadElementSection,
}

func loadCustomSection(m *Module, config *ModuleConfig, payloadLen uint32, load *loader.L) {
	var err error
	if config.CustomSectionLoader != nil {
		err = config.CustomSectionLoader(load, payloadLen)
	} else {
		_, err = io.CopyN(ioutil.Discard, load, int64(payloadLen))
	}
	if err != nil {
		panic(err)
	}
}

func loadTypeSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) {
	count := load.Count(module.MaxTypes, "type")
	m.m.Types = make([]wa.FuncType, 0, count)

	for i := 0; i < count; i++ {
		if form := load.Varint7(); form != -0x20 {
			panic(module.Errorf("unsupported function type form: %d", form))
		}

		var sig wa.FuncType

		paramCount := load.Varuint32()
		if paramCount > module.MaxFuncParams {
			panic(module.Errorf("function type #%d has too many parameters: %d", i, paramCount))
		}

		sig.Params = make([]wa.Type, paramCount)
		for j := range sig.Params {
			sig.Params[j] = typedecode.Value(load.Varint7())
		}

		switch load.Byte() {
		case 0:
		case 1:
			sig.Result = typedecode.Value(load.Varint7())
		default:
			panic(module.Error("multiple return values not supported"))
		}

		m.m.Types = append(m.m.Types, sig)
	}
}

func loadImportSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) {
	for i := range load.Span(module.MaxImports, "import") {
		moduleLen := load.Varuint32()
		if moduleLen > maxStringSize {
			panic(module.Errorf("module string is too long in import #%d", i))
		}

		moduleStr := load.String(moduleLen, "imported module name")

		fieldLen := load.Varuint32()
		if fieldLen > maxStringSize {
			panic(module.Errorf("field string is too long in import #%d", i))
		}

		fieldStr := load.String(fieldLen, "imported field name")

		kind := module.ExternalKind(load.Byte())

		switch kind {
		case module.ExternalKindFunction:
			sigIndex := load.Varuint32()
			if sigIndex >= uint32(len(m.m.Types)) {
				panic(module.Errorf("function type index out of bounds in import #%d: 0x%x", i, sigIndex))
			}

			m.m.Funcs = append(m.m.Funcs, sigIndex)

			m.m.ImportFuncs = append(m.m.ImportFuncs, module.ImportFunc{
				Import: module.Import{
					Module: moduleStr,
					Field:  fieldStr,
				},
				LibraryFunc: math.MaxUint32, // Outrageous value by default.
			})

		case module.ExternalKindGlobal:
			if len(m.m.Globals) >= maxGlobals {
				panic(module.Error("too many imported globals"))
			}

			t := typedecode.Value(load.Varint7())

			if mutable := load.Varuint1(); mutable {
				panic(module.Errorf("unsupported mutable global in import #%d", i))
			}

			m.m.Globals = append(m.m.Globals, module.Global{
				Type:       t,
				InitImport: -128, // Invalid value as placeholder.
			})

			m.m.ImportGlobals = append(m.m.ImportGlobals, module.Import{
				Module: moduleStr,
				Field:  fieldStr,
			})

		default:
			panic(module.Errorf("import kind not supported: %s", kind))
		}
	}
}

func loadFunctionSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) {
	count := load.Count(module.MaxFunctions-len(m.m.Funcs), "function")
	total := len(m.m.Funcs) + count
	if cap(m.m.Funcs) < total {
		m.m.Funcs = append(make([]uint32, 0, total), m.m.Funcs...)
	}

	for i := 0; i < count; i++ {
		sigIndex := load.Varuint32()
		if sigIndex >= uint32(len(m.m.Types)) {
			panic(module.Errorf("function type index out of bounds: %d", sigIndex))
		}

		m.m.Funcs = append(m.m.Funcs, sigIndex)
	}
}

func loadTableSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) {
	switch load.Varuint32() {
	case 0:

	case 1:
		if elementType := load.Varint7(); elementType != -0x10 {
			panic(module.Errorf("unsupported table element type: %d", elementType))
		}

		m.m.TableLimit = readResizableLimits(load, maxTableLen, maxTableLen, 0, 1, "table")
		if m.m.TableLimit.Max < 0 {
			m.m.TableLimit.Max = maxTableLen
		}

	default:
		panic(module.Error("multiple tables not supported"))
	}
}

func loadMemorySection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) {
	switch load.Varuint32() {
	case 0:

	case 1:
		m.m.MemoryLimit = readResizableLimits(load, maxMemoryPages, maxMemoryPages, 65536, wa.PageSize, "memory")

	default:
		panic(module.Error("multiple memories not supported"))
	}
}

func loadGlobalSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) {
	total := len(m.m.Globals) + load.Count(maxGlobals-len(m.m.Globals), "global")
	if cap(m.m.Globals) < total {
		m.m.Globals = append(make([]module.Global, 0, total), m.m.Globals...)
	}

	for i := len(m.m.Globals); i < total; i++ {
		globalType := typedecode.Value(load.Varint7())
		mutable := load.Varuint1()
		index, value, exprType := initexpr.Read(&m.m, load)

		if exprType != globalType {
			panic(module.Errorf("%s global #%d initializer expression has wrong type: %s", globalType, i, exprType))
		}

		m.m.Globals = append(m.m.Globals, module.Global{
			Type:       globalType,
			Mutable:    mutable,
			InitImport: int8(index), // Assumes that maxGlobals is small.
			InitConst:  value,
		})
	}
}

func loadExportSection(m *Module, config *ModuleConfig, _ uint32, load *loader.L) {
	count := load.Count(config.MaxExports, "export")
	names := make(map[string]struct{}, count)

	m.m.ExportFuncs = make(map[string]uint32)

	for i := 0; i < count; i++ {
		fieldLen := load.Varuint32()
		if fieldLen > maxStringSize {
			panic(module.Errorf("field string is too long in export #%d", i))
		}

		fieldStr := load.String(fieldLen, "exported field name")
		kind := module.ExternalKind(load.Byte())
		index := load.Varuint32()

		if _, exist := names[fieldStr]; exist {
			panic(module.Errorf("duplicate export name: %q", fieldStr))
		}
		names[fieldStr] = struct{}{}

		switch kind {
		case module.ExternalKindFunction:
			if index >= uint32(len(m.m.Funcs)) {
				panic(module.Errorf("export function index out of bounds: %d", index))
			}
			m.m.ExportFuncs[fieldStr] = index

		case module.ExternalKindTable, module.ExternalKindMemory, module.ExternalKindGlobal:

		default:
			panic(module.Errorf("custom export kind: %s", kind))
		}
	}
}

func loadStartSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) {
	index := load.Varuint32()
	if index >= uint32(len(m.m.Funcs)) {
		panic(module.Errorf("start function index out of bounds: %d", index))
	}

	sigIndex := m.m.Funcs[index]
	sig := m.m.Types[sigIndex]
	if len(sig.Params) > 0 || sig.Result != wa.Void {
		panic(module.Errorf("invalid start function signature: %s", sig))
	}

	m.m.StartIndex = index
	m.m.StartDefined = true
}

func loadElementSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) {
	for i := range load.Span(maxElements, "element") {
		if index := load.Varuint32(); index != 0 {
			panic(module.Errorf("unsupported table index: %d", index))
		}

		offset := initexpr.ReadOffset(&m.m, load)

		numElem := load.Varuint32()

		needSize := uint64(offset) + uint64(numElem)
		if needSize > uint64(m.m.TableLimit.Init) {
			panic(module.Errorf("table segment #%d exceeds initial table size", i))
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
				panic(module.Errorf("table element index out of bounds: %d", elem))
			}

			m.m.TableFuncs[j] = elem
		}
	}
}

func (m Module) Types() []wa.FuncType      { return m.m.Types }
func (m Module) FuncTypeIndexes() []uint32 { return m.m.Funcs }

func (m Module) FuncTypes() []wa.FuncType {
	sigs := make([]wa.FuncType, len(m.m.Funcs))
	for i, sigIndex := range m.m.Funcs {
		sigs[i] = m.m.Types[sigIndex]
	}
	return sigs
}

func (m Module) InitialMemorySize() int { return m.m.MemoryLimit.Init }
func (m Module) MemorySizeLimit() int   { return m.m.MemoryLimit.Max }

func (m Module) GlobalTypes() []wa.GlobalType {
	gs := make([]wa.GlobalType, len(m.m.Globals))
	for i, g := range m.m.Globals {
		gs[i] = wa.MakeGlobalType(g.Type, g.Mutable)
	}
	return gs
}

func (m Module) NumImportFuncs() int   { return len(m.m.ImportFuncs) }
func (m Module) NumImportGlobals() int { return len(m.m.ImportGlobals) }

func (m Module) ImportFunc(i int) (module, field string, sig wa.FuncType) {
	imp := m.m.ImportFuncs[i]
	module = imp.Module
	field = imp.Field

	sigIndex := m.m.Funcs[i]
	sig = m.m.Types[sigIndex]
	return
}

func (m Module) ImportGlobal(i int) (module, field string, t wa.Type) {
	imp := m.m.ImportGlobals[i]
	module = imp.Module
	field = imp.Field

	t = m.m.Globals[i].Type
	return
}

func (m *Module) SetImportFunc(i int, libFunc uint32) {
	m.m.ImportFuncs[i].LibraryFunc = libFunc
}

func (m *Module) SetImportGlobal(i int, value uint64) {
	m.m.Globals[i].InitImport = -1
	m.m.Globals[i].InitConst = value
}

func (m Module) GlobalsSize() int {
	size := len(m.m.Globals) * obj.Word
	mask := datalayout.MinAlignment - 1 // Round up so that linear memory will
	return (size + mask) &^ mask        // have at least minimum alignment.
}

func (m Module) ExportFuncs() map[string]uint32 { return m.m.ExportFuncs }

func (m Module) ExportFunc(field string) (funcIndex uint32, sig wa.FuncType, found bool) {
	funcIndex, found = m.m.ExportFuncs[field]
	if found {
		sigIndex := m.m.Funcs[funcIndex]
		sig = m.m.Types[sigIndex]
	}
	return
}

func (m Module) StartFunc() (funcIndex uint32, defined bool) {
	funcIndex = m.m.StartIndex
	defined = m.m.StartDefined
	return
}

// CodeConfig for a single compiler invocation.
//
// MaxTextSize field limits memory allocations only when Text field is not
// specified.  To limit memory allocations when providing a custom CodeBuffer
// implementation, the implementation must take care of it.
type CodeConfig struct {
	MaxTextSize  int        // Set to MaxTextSize if unspecified or too large.
	Text         CodeBuffer // Initialized with default implementation if nil.
	Mapper       ObjectMapper
	EventHandler func(event.Event)
	LastInitFunc uint32
	Breakpoints  map[uint32]Breakpoint
	Config
}

// LoadCodeSection reads a WebAssembly module's code section and generates
// machine code.
//
// If CodeBuffer panicks with an error, it will be returned by this function.
func LoadCodeSection(config *CodeConfig, r Reader, mod Module, lib Library) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	loadCodeSection(config, r, mod, &lib.l)
	return
}

func loadCodeSection(config *CodeConfig, r Reader, mod Module, lib *module.Library) {
	var payloadLen uint32

	load := loader.New(r)

	switch id := section.Find(module.SectionCode, load, config.SectionMapper, config.CustomSectionLoader); id {
	case module.SectionData, 0:
		// No code section, but compiler needs to generate init routines.
		load = loader.New(bytes.NewReader(emptyCodeSectionPayload))
		payloadLen = uint32(len(emptyCodeSectionPayload))

	case module.SectionCode:
		if config.SectionMapper != nil {
			var err error
			payloadLen, err = config.SectionMapper(byte(id), load)
			if err != nil {
				panic(err)
			}
		} else {
			payloadLen = load.Varuint32()
		}

	default:
		panic(module.Errorf("unexpected section id: 0x%x (looking for code section)", id))
	}

	if config.MaxTextSize == 0 || config.MaxTextSize > MaxTextSize {
		config.MaxTextSize = MaxTextSize
	}

	if config.Text == nil {
		alloc := defaultTextBufferSize
		if alloc > config.MaxTextSize {
			alloc = config.MaxTextSize
		}
		if guess := 512 + uint64(payloadLen)*8; guess < uint64(alloc) { // citation needed
			alloc = int(guess)
		}
		config.Text = buffer.NewLimited(make([]byte, 0, alloc), config.MaxTextSize)
	}

	mapper := config.Mapper
	if mapper == nil {
		mapper = obj.DummyMapper{}
	}

	codegen.GenProgram(config.Text, mapper, load, &mod.m, lib, config.EventHandler, int(config.LastInitFunc)+1, config.Breakpoints)

	if len(config.Text.Bytes()) > config.MaxTextSize {
		panic(module.Error("text size limit exceeded"))
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
//
// If DataBuffer panicks with an error, it will be returned by this function.
func LoadDataSection(config *DataConfig, r Reader, mod Module) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	loadDataSection(config, r, mod)
	return
}

func loadDataSection(config *DataConfig, r Reader, mod Module) {
	if config.MemoryAlignment == 0 {
		config.MemoryAlignment = datalayout.MinAlignment
	}
	memoryOffset := datalayout.MemoryOffset(&mod.m, config.MemoryAlignment)

	load := loader.New(r)

	switch id := section.Find(module.SectionData, load, config.SectionMapper, config.CustomSectionLoader); id {
	case module.SectionData:
		var payloadLen uint32
		var err error

		if config.SectionMapper != nil {
			payloadLen, err = config.SectionMapper(byte(id), load)
			if err != nil {
				panic(err)
			}
		} else {
			payloadLen = load.Varuint32()
		}

		if config.GlobalsMemory == nil {
			memAlloc := defaultMemoryBufferSize
			if payloadLen < uint32(memAlloc) {
				memAlloc = int(payloadLen) // hope for dense packing
			}

			limit := memoryOffset + mod.InitialMemorySize()
			alloc := memoryOffset + memAlloc
			if alloc > limit {
				alloc = limit
			}

			config.GlobalsMemory = buffer.NewDynamicHint(make([]byte, 0, alloc), limit)
		}

		datalayout.CopyGlobalsAlign(config.GlobalsMemory, &mod.m, memoryOffset)
		datalayout.ReadMemory(config.GlobalsMemory, load, &mod.m)

	case 0:
		// no data section

		if config.GlobalsMemory == nil {
			config.GlobalsMemory = buffer.NewStatic(make([]byte, 0, memoryOffset))
		}

		datalayout.CopyGlobalsAlign(config.GlobalsMemory, &mod.m, memoryOffset)

	default:
		panic(module.Errorf("unexpected section id: 0x%x (looking for data section)", id))
	}
}

// ValidateDataSection reads a WebAssembly module's data section.
func ValidateDataSection(config *Config, r Reader, mod Module) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	validateDataSection(config, r, mod)
	return
}

func validateDataSection(config *Config, r Reader, mod Module) {
	if config == nil {
		config = new(Config)
	}

	load := loader.New(r)

	switch id := section.Find(module.SectionData, load, config.SectionMapper, config.CustomSectionLoader); id {
	case module.SectionData:
		if config.SectionMapper != nil {
			_, err := config.SectionMapper(byte(id), load)
			if err != nil {
				panic(err)
			}
		} else {
			load.Varuint32()
		}

		datalayout.ValidateMemory(load, &mod.m)

	case 0:
		// no data section

	default:
		panic(module.Errorf("unexpected section id: 0x%x (looking for data section)", id))
	}
}

// LoadCustomSections reads WebAssembly module's extension sections.
func LoadCustomSections(config *Config, r Reader) (err error) {
	defer func() {
		err = errorpanic.Handle(recover())
	}()

	loadCustomSections(config, r)
	return
}

func loadCustomSections(config *Config, r Reader) {
	if config == nil {
		config = new(Config)
	}

	load := loader.New(r)

	section.Find(0, load, config.SectionMapper, config.CustomSectionLoader)
}
