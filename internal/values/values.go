package values

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type Storage int

const (
	Nowhere = Storage(iota)
	Imm
	ROData
	Var
	TempReg
	Stack
	ConditionFlags
)

var (
	NoOperand    = Operand{Storage: Nowhere}
	StackOperand = Operand{Storage: Stack}
)

type Condition int

const (
	EQ = Condition(iota)
	NE
	GE_S
	GT_S
	GE_U
	GT_U
	LE_S
	LT_S
	LE_U
	LT_U
)

var InvertedConditions = []Condition{
	NE,   // EQ
	EQ,   // NE
	LT_S, // GE_S
	LE_S, // GT_S
	LT_U, // GE_U
	LE_U, // GT_U
	GT_S, // LE_S
	GE_S, // LT_U
	GT_U, // LE_U
	GE_U, // LT_U
}

type Operand struct {
	Storage Storage
	X       uint64
}

func ImmOperand(t types.T, value int) Operand {
	var x uint64

	switch t.Size() {
	case types.Size32:
		x = uint64(uint32(int32(value)))

	case types.Size64:
		x = uint64(int64(value))

	default:
		panic(t)
	}

	return Operand{Imm, x}
}

func RODataOperand(addr int) Operand {
	return Operand{ROData, uint64(addr)}
}

func TempRegOperand(reg regs.R) Operand {
	return Operand{TempReg, uint64(byte(reg))}
}

func VarOperand(index int) Operand {
	return Operand{Var, uint64(index)}
}

func ConditionFlagsOperand(cond Condition) Operand {
	return Operand{ConditionFlags, uint64(int(cond))}
}

func (o Operand) Imm(t types.T) (imm interface{}) {
	imm, ok := o.CheckImm(t)
	if !ok {
		panic(o)
	}
	return
}

func (o Operand) CheckImm(t types.T) (imm interface{}, ok bool) {
	if o.Storage != Imm {
		return
	}

	switch t.Size() {
	case types.Size32:
		imm = uint32(o.X)

	case types.Size64:
		imm = o.X

	default:
		panic(t)
	}

	ok = true
	return
}

func (o Operand) ImmValue(t types.T) (value int64) {
	value, ok := o.CheckImmValue(t)
	if !ok {
		panic(o)
	}
	return
}

func (o Operand) CheckImmValue(t types.T) (value int64, ok bool) {
	if o.Storage != Imm {
		return
	}

	switch t.Size() {
	case types.Size32:
		value = int64(int32(uint32(o.X)))

	case types.Size64:
		value = int64(o.X)

	default:
		panic(t)
	}

	ok = true
	return
}

func (o Operand) Addr() (addr int) {
	addr, ok := o.CheckROData()
	if !ok {
		panic(o)
	}
	return
}

func (o Operand) CheckROData() (addr int, ok bool) {
	if o.Storage != ROData {
		return
	}

	if o.X >= 0x80000000-8 {
		panic(o)
	}

	addr = int(o.X)
	ok = true
	return
}

func (o Operand) Index() (index int) {
	index, ok := o.CheckVar()
	if !ok {
		panic(o)
	}
	return
}

func (o Operand) CheckVar() (index int, ok bool) {
	if o.Storage == Var {
		index = int(o.X)
		ok = true
	}
	return
}

func (o Operand) Reg() (reg regs.R) {
	reg, ok := o.CheckTempReg()
	if !ok {
		panic(o)
	}
	return
}

func (o Operand) CheckTempReg() (reg regs.R, ok bool) {
	if o.Storage == TempReg {
		reg = regs.R(byte(o.X))
		ok = true
	}
	return
}

func (o Operand) Condition() (cond Condition) {
	cond, ok := o.CheckConditionFlags()
	if !ok {
		panic(o)
	}
	return
}

func (o Operand) CheckConditionFlags() (cond Condition, ok bool) {
	if o.Storage == ConditionFlags {
		cond = Condition(int(o.X))
		ok = true
	}
	return
}

func (o Operand) String() string {
	switch o.Storage {
	case Nowhere:
		return "nowhere"

	case Imm:
		return fmt.Sprintf("immediate data 0x%x", o.X)

	case ROData:
		return fmt.Sprintf("read-only data at 0x%x", o.X)

	case Var:
		return fmt.Sprintf("variable #%d", o.X)

	case TempReg:
		return fmt.Sprintf("temporary register r%d", o.X)

	case Stack:
		return "stack"

	case ConditionFlags:
		return "condition flags"

	default:
		return "corrupted"
	}
}

func ParseImm(t types.T, x interface{}) Operand {
	var value uint64

	switch t {
	case types.I32:
		value = ParseI32(x)

	case types.I64:
		value = ParseI64(x)

	case types.F32:
		value = ParseF32(x)

	case types.F64:
		value = ParseF64(x)

	default:
		panic(t)
	}

	return Operand{Imm, value}
}

func ParseI32(x interface{}) uint64 {
	s := nonOctalize(x.(string))

	signed64, err := strconv.ParseInt(s, 0, 32)
	if err == nil {
		return uint64(signed64)
	}

	unsigned64, err := strconv.ParseUint(s, 0, 32)
	if err == nil {
		return unsigned64
	}

	panic(err)
}

func ParseI64(x interface{}) uint64 {
	s := nonOctalize(x.(string))

	signed64, err := strconv.ParseInt(s, 0, 64)
	if err == nil {
		return uint64(signed64)
	}

	unsigned64, err := strconv.ParseUint(s, 0, 64)
	if err == nil {
		return unsigned64
	}

	panic(err)
}

func ParseF32(x interface{}) uint64 {
	s := x.(string)

	value64, err := strconv.ParseFloat(s, 32)
	if err == nil {
		return uint64(math.Float32bits(float32(value64)))
	}

	panic(err)
}

func ParseF64(x interface{}) uint64 {
	s := x.(string)

	value64, err := strconv.ParseFloat(s, 64)
	if err == nil {
		return math.Float64bits(value64)
	}

	panic(err)
}

func nonOctalize(s string) string {
	for len(s) > 1 && strings.HasPrefix(s, "0") && !strings.HasPrefix(s, "0x") {
		s = s[1:]
	}

	return s
}
