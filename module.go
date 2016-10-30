package wag

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/types"
	"github.com/tsavola/wag/wasm"
)

type Environment interface {
	ImportFunction(module, field string, sig types.Function) (variadic bool, absAddr uint64, err error)
	ImportGlobal(module, field string, t types.T) (valueBits uint64, err error)
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

const (
	resizableLimitsFlagMaximum = 0x1
)

type resizableLimits struct {
	initial int
	maximum int
	defined bool
}

func readResizableLimits(r reader, maxInitial, maxMaximum uint32, scale int) resizableLimits {
	flags := r.readVaruint32()

	initial := r.readVaruint32()
	if initial > maxInitial {
		panic(fmt.Errorf("initial memory size is too large: %d", initial))
	}

	maximum := maxMaximum

	if (flags & resizableLimitsFlagMaximum) != 0 {
		maximum = r.readVaruint32()
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
	moduleVersion     = uint32(0xd)
)

const (
	sectionUnknown = iota
	sectionType
	sectionImport
	sectionFunction
	sectionTable
	sectionMemory
	sectionGlobal
	sectionExport
	sectionStart
	sectionElement
	sectionCode
	sectionData

	numSections
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
	sigs             []types.Function
	funcSigs         []uint32
	importFuncs      []importFunction
	tableLimits      resizableLimits
	memoryLimits     resizableLimits
	globals          []global
	numImportGlobals int
	startIndex       uint32
	startDefined     bool
	tableFuncs       []uint32

	text          *bytes.Buffer
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
func (m *Module) LoadPreliminarySections(r Reader, env Environment) (err error) {
	defer func() {
		err = apiError(recover())
	}()

	m.loadPreliminarySections(r, env)
	return
}

func (m *Module) loadPreliminarySections(r Reader, env Environment) {
	moduleLoader{m, env, nil}.loadUntil(reader{r}, sectionCode)
}

// Load all (remaining) sections.
func (m *Module) Load(r Reader, env Environment, textBuf, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) (err error) {
	defer func() {
		err = apiError(recover())
	}()

	m.load(r, env, textBuf, roDataBuf, roDataAbsAddr, startTrigger)
	return
}

func (m *Module) load(r Reader, env Environment, textBuf, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) {
	if textBuf != nil {
		m.text = bytes.NewBuffer(textBuf[:0])
	}

	m.roData.buf = roDataBuf[:0]
	m.roDataAbsAddr = roDataAbsAddr

	moduleLoader{m, env, startTrigger}.load(reader{r})
}

type moduleLoader struct {
	*Module
	env          Environment
	startTrigger chan<- struct{}
}

func (m moduleLoader) load(r reader) {
	nextId := m.loadUntil(r, numSections)
	if nextId != 0 {
		panic(fmt.Errorf("unknown section id: 0x%x", nextId))
	}
}

func (m moduleLoader) loadUntil(r reader, untilSection byte) byte {
	var header struct {
		MagicNumber uint32
		Version     uint32
	}
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		panic(err)
	}
	if header.MagicNumber != moduleMagicNumber {
		panic(errors.New("not a WebAssembly module"))
	}
	if header.Version != moduleVersion {
		panic(fmt.Errorf("unsupported module version: %d", header.Version))
	}

	var seenId byte

	for {
		id, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0
			}
			panic(err)
		}

		if id != sectionUnknown {
			if id <= seenId {
				panic(fmt.Errorf("section 0x%x follows section 0x%x", id, seenId))
			}
			seenId = id
		}

		if id >= untilSection {
			r.UnreadByte()
			return id
		}

		payloadLen := r.readVaruint32()

		if f := sectionLoaders[id]; f != nil {
			f(m, r)
		} else {
			if _, err := io.CopyN(ioutil.Discard, r, int64(payloadLen)); err != nil {
				panic(err)
			}
		}
	}
}

var sectionLoaders = []func(moduleLoader, reader){
	sectionType: func(m moduleLoader, r reader) {
		for i := range r.readCount() {
			if form := r.readVarint7(); form != -0x20 {
				panic(fmt.Errorf("unsupported function type form: %d", form))
			}

			var sig types.Function

			paramCount := r.readVaruint32()
			if paramCount > maxFunctionParams {
				panic(fmt.Errorf("function type #%d has too many parameters: %d", i, paramCount))
			}

			sig.Args = make([]types.T, paramCount)
			for j := range sig.Args {
				sig.Args[j] = types.ByEncoding(r.readVarint7())
			}

			if returnCount1 := r.readVaruint1(); returnCount1 {
				sig.Result = types.ByEncoding(r.readVarint7())
			}

			m.sigs = append(m.sigs, sig)
		}
	},

	sectionImport: func(m moduleLoader, r reader) {
		for i := range r.readCount() {
			moduleLen := r.readVaruint32()
			if moduleLen > maxStringLen {
				panic(fmt.Errorf("module string is too long in import #%d", i))
			}

			moduleStr := string(r.readN(moduleLen))

			fieldLen := r.readVaruint32()
			if fieldLen > maxStringLen {
				panic(fmt.Errorf("field string is too long in import #%d", i))
			}

			fieldStr := string(r.readN(fieldLen))

			kind := externalKind(r.readByte())

			switch kind {
			case externalKindFunction:
				sigIndex := r.readVaruint32()
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
				t := types.ByEncoding(r.readVarint7())

				mutable := r.readVaruint1()
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

	sectionFunction: func(m moduleLoader, r reader) {
		for range r.readCount() {
			sigIndex := r.readVaruint32()
			if sigIndex >= uint32(len(m.sigs)) {
				panic(fmt.Errorf("function type index out of bounds: %d", sigIndex))
			}

			m.funcSigs = append(m.funcSigs, sigIndex)
		}
	},

	sectionTable: func(m moduleLoader, r reader) {
		for range r.readCount() {
			if m.tableLimits.defined {
				panic(errors.New("multiple tables not supported"))
			}

			if elementType := r.readVarint7(); elementType != -0x10 {
				panic(fmt.Errorf("unsupported table element type: %d", elementType))
			}

			m.tableLimits = readResizableLimits(r, maxTableLimit, maxTableLimit, 1)
		}
	},

	sectionMemory: func(m moduleLoader, r reader) {
		for range r.readCount() {
			if m.memoryLimits.defined {
				panic(errors.New("multiple memories not supported"))
			}

			m.memoryLimits = readResizableLimits(r, maxInitialMemoryLimit, maxMaximumMemoryLimit, int(wasm.Page))
		}
	},

	sectionGlobal: func(m moduleLoader, r reader) {
		// TODO: limit number of globals
		for range r.readCount() {
			t := types.ByEncoding(r.readVarint7())
			mutable := r.readVaruint1()
			init, _ := readInitExpr(r, m.Module)

			m.globals = append(m.globals, global{t, mutable, init})
		}

		m.data = appendGlobalsData(m.data, m.globals[m.numImportGlobals:])
		m.memoryOffset = len(m.data)
	},

	sectionStart: func(m moduleLoader, r reader) {
		index := r.readVaruint32()
		if index >= uint32(len(m.funcSigs)) {
			panic(fmt.Errorf("start function index out of bounds: %d", index))
		}

		sigIndex := m.funcSigs[index]
		sig := m.sigs[sigIndex]
		if len(sig.Args) > 0 || sig.Result != types.Void {
			panic(errors.New("invalid start function signature"))
		}

		m.startIndex = index
		m.startDefined = true
	},

	sectionElement: func(m moduleLoader, r reader) {
		for i := range r.readCount() {
			if index := r.readVaruint32(); index != 0 {
				panic(fmt.Errorf("unsupported table index: %d", index))
			}

			offset := readOffsetInitExpr(r, m.Module)

			numElem := r.readVaruint32()

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
				elem := r.readVaruint32()
				if elem >= uint32(len(m.funcSigs)) {
					panic(fmt.Errorf("table element index out of bounds: %d", elem))
				}

				m.tableFuncs[j] = elem
			}
		}
	},

	sectionCode: func(m moduleLoader, r reader) {
		moduleCoder{m.Module}.genCode(r, m.startTrigger)
	},

	sectionData: func(m moduleLoader, r reader) {
		m.genData(r)
	},
}

// LoadCodeSection, after loading the preliminary sections.
func (m *Module) LoadCodeSection(r Reader, textBuf, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) (err error) {
	defer func() {
		err = apiError(recover())
	}()

	m.loadCodeSection(r, textBuf, roDataBuf, roDataAbsAddr, startTrigger)
	return
}

func (m *Module) loadCodeSection(R Reader, textBuf, roDataBuf []byte, roDataAbsAddr int32, startTrigger chan<- struct{}) {
	if m.funcLinks != nil {
		panic(errors.New("code section has already been loaded"))
	}

	if textBuf != nil {
		m.text = bytes.NewBuffer(textBuf[:0])
	}

	m.roData.buf = roDataBuf[:0]
	m.roDataAbsAddr = roDataAbsAddr

	r := reader{R}

	if readSectionHeader(r, sectionCode, "not a code section") {
		moduleCoder{m}.genCode(r, startTrigger)
	}
}

// LoadDataSection, after loading the preliminary sections.
func (m *Module) LoadDataSection(r Reader) (err error) {
	defer func() {
		err = apiError(recover())
	}()

	m.loadDataSection(r)
	return
}

func (m *Module) loadDataSection(R Reader) {
	r := reader{R}

	if readSectionHeader(r, sectionData, "not a data section") {
		m.genData(r)
	}
}

func readSectionHeader(r reader, expectId byte, idError string) (ok bool) {
	id, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return
		}
		panic(err)
	}

	if id != expectId {
		panic(errors.New(idError))
	}

	r.readVaruint32() // payload len

	ok = true
	return
}

// Signatures are available after preliminary sections have been loaded.
func (m *Module) Signatures() []types.Function {
	return m.sigs
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
