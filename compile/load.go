// Copyright (c) 2015 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package compile implements a WebAssembly compiler.

# Text

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

# Globals and memory

The memory, global and data sections comprise a single mutable buffer.

# Stack

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
	"gate.computer/wag/internal"
	"gate.computer/wag/internal/code"
	"gate.computer/wag/internal/data"
	"gate.computer/wag/internal/datalayout"
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/codegen"
	"gate.computer/wag/internal/initexpr"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/internal/section"
	"gate.computer/wag/internal/typedecode"
	"gate.computer/wag/wa"
	"import.name/pan"

	. "import.name/pan/mustcheck"
)

// Some limits have been chosen based on the backends' limitations:
//
// - MaxTextSize is the range supported by ARM64 branch instructions.
//
// - maxGlobals * -obj.Word is the smallest offset which can be encoded in an
//   ARM64 load instruction.
//
// - All limits are small enough to keep values below 2^31, so that simple
//   signed 32-bit comparisons can be used by the amd64 backend.
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

// Reader is suitable for reading a module.
type Reader = binary.Reader

// Loader is suitable for use with module loading functions.
type Loader = loader.Loader

// NewLoader creates a WebAssembly module loader.
func NewLoader(r binary.Reader) Loader {
	return loader.New(r, 0)
}

type (
	CodeBuffer = code.Buffer
	DataBuffer = data.Buffer
)

type (
	ModuleMapper      = section.ModuleMapper
	ObjectMapper      = obj.ObjectMapper
	DebugObjectMapper = obj.DebugObjectMapper
)

type Breakpoint = gen.Breakpoint

func readResizableLimits(load *loader.L, maxInit, maxMax, maxValid uint32, scale int, kind string) module.ResizableLimits {
	maxFieldIsPresent := load.Varuint1()

	init := load.Varuint32()
	if maxValid > 0 && init > maxValid {
		pan.Panic(module.Errorf("invalid initial %s size: %d pages", kind, init))
	}
	if init > maxInit {
		pan.Panic(module.Errorf("initial %s size is too large: %d", kind, init))
	}

	limits := module.ResizableLimits{
		Init: int(init) * scale,
		Max:  -1,
	}

	if maxFieldIsPresent {
		max := load.Varuint32()
		if maxValid > 0 && max > maxValid {
			pan.Panic(module.Errorf("invalid maximum %s size: %d pages", kind, max))
		}
		if max > maxMax {
			max = maxMax
		}
		if max < init {
			pan.Panic(module.Errorf("maximum %s size %d is smaller than initial %s size %d", kind, max, kind, init))
		}
		limits.Max = int(max) * scale
	}

	return limits
}

// Config for loading WebAssembly module sections.
type Config struct {
	// ModuleMapper (if set) is called for every section (standard or custom).
	ModuleMapper ModuleMapper

	// CustomSectionLoader (if set) is invoked for every custom section.  It
	// must read exactly payloadSize bytes, or return an error.  ModuleMapper
	// has been invoked just before it.
	//
	// If the section.Unwrapped error is returned, the consumed length may be
	// less than payloadSize.  The rest of the payload will be treated as
	// another section.  (The Unwrapped value itself must be returned, not an
	// error wrapping it.)
	CustomSectionLoader func(r Reader, payloadSize uint32) error
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
func LoadInitialSections(config *ModuleConfig, r Loader) (m Module, err error) {
	if internal.DontPanic() {
		defer func() { err = internal.Error(recover()) }()
	}

	m = loadInitialSections(config, loader.Get(r))
	return
}

func loadInitialSections(config *ModuleConfig, load *loader.L) (m Module) {
	if config == nil {
		config = new(ModuleConfig)
	}
	if config.MaxExports > math.MaxInt32 {
		panic("ModuleConfig.MaxExports is too large")
	} else if config.MaxExports == 0 {
		config.MaxExports = defaultMaxExports
	}

	var header module.Header
	Check(encodingbinary.Read(load, encodingbinary.LittleEndian, &header))
	if header.MagicNumber != module.MagicNumber {
		pan.Panic(module.Error("not a WebAssembly module"))
	}
	if header.Version != module.Version {
		pan.Panic(module.Errorf("unsupported module version: %d", header.Version))
	}

	var seenID module.SectionID

	for {
		sectionOffset := load.Tell()

		sectionID, err := load.ReadByte()
		if err == io.EOF {
			return
		}
		Check(err)

		id := module.SectionID(sectionID)

		if id != module.SectionCustom {
			if id <= seenID {
				pan.Panic(module.Errorf("%s section follows %s section", id, seenID))
			}
			seenID = id
		}

		if id > module.SectionElement {
			load.UnreadByte()
			if id >= module.NumSections {
				pan.Panic(module.Errorf("invalid section id: %d", byte(id)))
			}
			return
		}

		payloadSize := section.LoadPayloadSize(sectionOffset, id, load, config.ModuleMapper)
		payloadOffset := load.Tell()
		partial := initialSectionLoaders[id](&m, config, payloadSize, load)
		section.CheckConsumption(load, payloadOffset, payloadSize, partial)
	}
}

var initialSectionLoaders = [module.SectionElement + 1]func(*Module, *ModuleConfig, uint32, *loader.L) bool{
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

func loadCustomSection(m *Module, config *ModuleConfig, payloadSize uint32, load *loader.L) bool {
	if config.CustomSectionLoader == nil {
		Must(io.CopyN(ioutil.Discard, load, int64(payloadSize)))
		return false
	}

	err := config.CustomSectionLoader(load, payloadSize)
	if err == section.Unwrapped {
		return true
	}
	Check(err)
	return false
}

func loadTypeSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) bool {
	count := load.Count(module.MaxTypes, "type")
	m.m.Types = make([]wa.FuncType, 0, count)

	for i := 0; i < count; i++ {
		if form := load.Varint7(); form != -0x20 {
			pan.Panic(module.Errorf("unsupported function type form: %d", form))
		}

		var sig wa.FuncType

		paramCount := load.Varuint32()
		if paramCount > module.MaxFuncParams {
			pan.Panic(module.Errorf("function type #%d has too many parameters: %d", i, paramCount))
		}

		sig.Params = make([]wa.Type, paramCount)
		for j := range sig.Params {
			sig.Params[j] = typedecode.Value(load.Varint7())
		}

		switch load.Byte() {
		case 0:
		case 1:
			sig.Results = []wa.Type{typedecode.Value(load.Varint7())}
		default:
			pan.Panic(module.Error("multiple return values not supported"))
		}

		m.m.Types = append(m.m.Types, sig)
	}

	return false
}

func loadImportSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) bool {
	for i := range load.Span(module.MaxImports, "import") {
		moduleLen := load.Varuint32()
		if moduleLen > maxStringSize {
			pan.Panic(module.Errorf("module string is too long in import #%d", i))
		}

		moduleStr := load.String(moduleLen, "imported module name")

		fieldLen := load.Varuint32()
		if fieldLen > maxStringSize {
			pan.Panic(module.Errorf("field string is too long in import #%d", i))
		}

		fieldStr := load.String(fieldLen, "imported field name")

		kind := module.ExternalKind(load.Byte())

		switch kind {
		case module.ExternalKindFunction:
			sigIndex := load.Varuint32()
			if sigIndex >= uint32(len(m.m.Types)) {
				pan.Panic(module.Errorf("function type index out of bounds in import #%d: 0x%x", i, sigIndex))
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
				pan.Panic(module.Error("too many imported globals"))
			}

			t := typedecode.Value(load.Varint7())

			if mutable := load.Varuint1(); mutable {
				pan.Panic(module.Errorf("unsupported mutable global in import #%d", i))
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
			pan.Panic(module.Errorf("import kind not supported: %s", kind))
		}
	}

	return false
}

func loadFunctionSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) bool {
	count := load.Count(module.MaxFunctions-len(m.m.Funcs), "function")
	total := len(m.m.Funcs) + count
	if cap(m.m.Funcs) < total {
		m.m.Funcs = append(make([]uint32, 0, total), m.m.Funcs...)
	}

	for i := 0; i < count; i++ {
		sigIndex := load.Varuint32()
		if sigIndex >= uint32(len(m.m.Types)) {
			pan.Panic(module.Errorf("function type index out of bounds: %d", sigIndex))
		}

		m.m.Funcs = append(m.m.Funcs, sigIndex)
	}

	return false
}

func loadTableSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) bool {
	switch load.Varuint32() {
	case 0:

	case 1:
		if elementType := load.Varint7(); elementType != -0x10 {
			pan.Panic(module.Errorf("unsupported table element type: %d", elementType))
		}

		m.m.TableLimit = readResizableLimits(load, maxTableLen, maxTableLen, 0, 1, "table")
		if m.m.TableLimit.Max < 0 {
			m.m.TableLimit.Max = maxTableLen
		}

	default:
		pan.Panic(module.Error("multiple tables not supported"))
	}

	return false
}

func loadMemorySection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) bool {
	switch load.Varuint32() {
	case 0:

	case 1:
		m.m.MemoryLimit = readResizableLimits(load, maxMemoryPages, maxMemoryPages, 65536, wa.PageSize, "memory")

	default:
		pan.Panic(module.Error("multiple memories not supported"))
	}

	return false
}

func loadGlobalSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) bool {
	total := len(m.m.Globals) + load.Count(maxGlobals-len(m.m.Globals), "global")
	if cap(m.m.Globals) < total {
		m.m.Globals = append(make([]module.Global, 0, total), m.m.Globals...)
	}

	for i := len(m.m.Globals); i < total; i++ {
		globalType := typedecode.Value(load.Varint7())
		mutable := load.Varuint1()
		index, value, exprType := initexpr.Read(&m.m, load)

		if exprType != globalType {
			pan.Panic(module.Errorf("%s global #%d initializer expression has wrong type: %s", globalType, i, exprType))
		}

		m.m.Globals = append(m.m.Globals, module.Global{
			Type:       globalType,
			Mutable:    mutable,
			InitImport: int8(index), // Assumes that maxGlobals is small.
			InitConst:  value,
		})
	}

	return false
}

func loadExportSection(m *Module, config *ModuleConfig, _ uint32, load *loader.L) bool {
	count := load.Count(config.MaxExports, "export")
	names := make(map[string]struct{}, count)

	m.m.ExportFuncs = make(map[string]uint32)

	for i := 0; i < count; i++ {
		fieldLen := load.Varuint32()
		if fieldLen > maxStringSize {
			pan.Panic(module.Errorf("field string is too long in export #%d", i))
		}

		fieldStr := load.String(fieldLen, "exported field name")
		kind := module.ExternalKind(load.Byte())
		index := load.Varuint32()

		if _, exist := names[fieldStr]; exist {
			pan.Panic(module.Errorf("duplicate export name: %q", fieldStr))
		}
		names[fieldStr] = struct{}{}

		switch kind {
		case module.ExternalKindFunction:
			if index >= uint32(len(m.m.Funcs)) {
				pan.Panic(module.Errorf("export function index out of bounds: %d", index))
			}
			m.m.ExportFuncs[fieldStr] = index

		case module.ExternalKindTable, module.ExternalKindMemory, module.ExternalKindGlobal:

		default:
			pan.Panic(module.Errorf("custom export kind: %s", kind))
		}
	}

	return false
}

func loadStartSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) bool {
	index := load.Varuint32()
	if index >= uint32(len(m.m.Funcs)) {
		pan.Panic(module.Errorf("start function index out of bounds: %d", index))
	}

	sigIndex := m.m.Funcs[index]
	sig := m.m.Types[sigIndex]
	if len(sig.Params) > 0 || len(sig.Results) > 0 {
		pan.Panic(module.Errorf("invalid start function signature: %s", sig))
	}

	m.m.StartIndex = index
	m.m.StartDefined = true
	return false
}

func loadElementSection(m *Module, _ *ModuleConfig, _ uint32, load *loader.L) bool {
	for i := range load.Span(maxElements, "element") {
		if index := load.Varuint32(); index != 0 {
			pan.Panic(module.Errorf("unsupported table index: %d", index))
		}

		offset := initexpr.ReadOffset(&m.m, load)

		numElem := load.Varuint32()

		needSize := uint64(offset) + uint64(numElem)
		if needSize > uint64(m.m.TableLimit.Init) {
			pan.Panic(module.Errorf("table segment #%d exceeds initial table size", i))
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
				pan.Panic(module.Errorf("table element index out of bounds: %d", elem))
			}

			m.m.TableFuncs[j] = elem
		}
	}

	return false
}

func (m *Module) Types() []wa.FuncType      { return m.m.Types }
func (m *Module) FuncTypeIndexes() []uint32 { return m.m.Funcs }

func (m *Module) FuncTypes() []wa.FuncType {
	sigs := make([]wa.FuncType, len(m.m.Funcs))
	for i, sigIndex := range m.m.Funcs {
		sigs[i] = m.m.Types[sigIndex]
	}
	return sigs
}

func (m *Module) InitialMemorySize() int { return m.m.MemoryLimit.Init }
func (m *Module) MemorySizeLimit() int   { return m.m.MemoryLimit.Max }

func (m *Module) GlobalTypes() []wa.GlobalType {
	gs := make([]wa.GlobalType, len(m.m.Globals))
	for i, g := range m.m.Globals {
		gs[i] = wa.MakeGlobalType(g.Type, g.Mutable)
	}
	return gs
}

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

func (m *Module) SetImportFunc(i int, libFunc uint32) {
	m.m.ImportFuncs[i].LibraryFunc = libFunc
}

func (m *Module) SetImportGlobal(i int, value uint64) {
	m.m.Globals[i].InitImport = -1
	m.m.Globals[i].InitConst = value
}

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

func (m *Module) StartFunc() (funcIndex uint32, defined bool) {
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
// If CodeBuffer panics with an error, it will be returned by this function.
func LoadCodeSection(config *CodeConfig, r Loader, mod Module, lib Library) (err error) {
	if internal.DontPanic() {
		defer func() { err = internal.Error(recover()) }()
	}

	loadCodeSection(config, loader.Get(r), mod, &lib.l)
	return
}

func loadCodeSection(config *CodeConfig, load *loader.L, mod Module, lib *module.Library) {
	var payloadSize uint32

	switch sectionOffset, id := section.Find(module.SectionCode, load, config.ModuleMapper, config.CustomSectionLoader); id {
	case module.SectionData, 0:
		// No code section, but compiler needs to generate init routines.  Use
		// bogus offsets to avoid possible confusion.
		load = loader.New(bytes.NewReader(emptyCodeSectionPayload), math.MaxUint32)
		payloadSize = uint32(len(emptyCodeSectionPayload))

	case module.SectionCode:
		payloadSize = section.LoadPayloadSize(sectionOffset, id, load, config.ModuleMapper)

	default:
		pan.Panic(module.Errorf("unexpected section id: 0x%x (looking for code section)", id))
	}

	if config.MaxTextSize == 0 || config.MaxTextSize > MaxTextSize {
		config.MaxTextSize = MaxTextSize
	}

	if config.Text == nil {
		alloc := defaultTextBufferSize
		if alloc > config.MaxTextSize {
			alloc = config.MaxTextSize
		}
		if guess := 512 + uint64(payloadSize)*8; guess < uint64(alloc) { // citation needed
			alloc = int(guess)
		}
		config.Text = buffer.NewLimited(make([]byte, 0, alloc), config.MaxTextSize)
	}

	mapper := config.Mapper
	if mapper == nil {
		mapper = obj.DummyMapper{}
	}

	payloadOffset := load.Tell()
	codegen.GenProgram(config.Text, mapper, load, &mod.m, lib, config.EventHandler, int(config.LastInitFunc)+1, config.Breakpoints)
	section.CheckConsumption(load, payloadOffset, payloadSize, false)

	if len(config.Text.Bytes()) > config.MaxTextSize {
		pan.Panic(module.Error("text size limit exceeded"))
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
// If DataBuffer panics with an error, it will be returned by this function.
func LoadDataSection(config *DataConfig, r Loader, mod Module) (err error) {
	if internal.DontPanic() {
		defer func() { err = internal.Error(recover()) }()
	}

	loadDataSection(config, loader.Get(r), mod)
	return
}

func loadDataSection(config *DataConfig, load *loader.L, mod Module) {
	if config.MemoryAlignment == 0 {
		config.MemoryAlignment = datalayout.MinAlignment
	}
	memoryOffset := datalayout.MemoryOffset(&mod.m, config.MemoryAlignment)

	switch sectionOffset, id := section.Find(module.SectionData, load, config.ModuleMapper, config.CustomSectionLoader); id {
	case module.SectionData:
		payloadSize := section.LoadPayloadSize(sectionOffset, id, load, config.ModuleMapper)

		if config.GlobalsMemory == nil {
			memAlloc := defaultMemoryBufferSize
			if payloadSize < uint32(memAlloc) {
				memAlloc = int(payloadSize) // hope for dense packing
			}

			limit := memoryOffset + mod.InitialMemorySize()
			alloc := memoryOffset + memAlloc
			if alloc > limit {
				alloc = limit
			}

			config.GlobalsMemory = buffer.NewDynamicHint(make([]byte, 0, alloc), limit)
		}

		datalayout.CopyGlobalsAlign(config.GlobalsMemory, &mod.m, memoryOffset)

		payloadOffset := load.Tell()
		datalayout.ReadMemory(config.GlobalsMemory, load, &mod.m)
		section.CheckConsumption(load, payloadOffset, payloadSize, false)

	case 0:
		// no data section

		if config.GlobalsMemory == nil {
			config.GlobalsMemory = buffer.NewStatic(make([]byte, 0, memoryOffset))
		}

		datalayout.CopyGlobalsAlign(config.GlobalsMemory, &mod.m, memoryOffset)

	default:
		pan.Panic(module.Errorf("unexpected section id: 0x%x (looking for data section)", id))
	}
}

// ValidateDataSection reads a WebAssembly module's data section.
func ValidateDataSection(config *Config, r Loader, mod Module) (err error) {
	if internal.DontPanic() {
		defer func() { err = internal.Error(recover()) }()
	}

	validateDataSection(config, loader.Get(r), mod)
	return
}

func validateDataSection(config *Config, load *loader.L, mod Module) {
	if config == nil {
		config = new(Config)
	}

	switch sectionOffset, id := section.Find(module.SectionData, load, config.ModuleMapper, config.CustomSectionLoader); id {
	case module.SectionData:
		payloadSize := section.LoadPayloadSize(sectionOffset, id, load, config.ModuleMapper)
		payloadOffset := load.Tell()
		datalayout.ValidateMemory(load, &mod.m)
		section.CheckConsumption(load, payloadOffset, payloadSize, false)

	case 0:
		// no data section

	default:
		pan.Panic(module.Errorf("unexpected section id: 0x%x (looking for data section)", id))
	}
}

// LoadCustomSections reads WebAssembly module's extension sections.
func LoadCustomSections(config *Config, r Loader) (err error) {
	if internal.DontPanic() {
		defer func() { err = internal.Error(recover()) }()
	}

	loadCustomSections(config, loader.Get(r))
	return
}

func loadCustomSections(config *Config, load *loader.L) {
	if config == nil {
		config = new(Config)
	}

	section.Find(0, load, config.ModuleMapper, config.CustomSectionLoader)
}
