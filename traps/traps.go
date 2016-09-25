package traps

type Id int

const (
	Exit = Id(iota)

	CallStackExhausted
	IndirectCallIndex
	IndirectCallSignature
	MemoryOutOfBounds
	Unreachable

	IntegerDivideByZero
	IntegerOverflow
)

func (id Id) String() string {
	switch id {
	case Exit:
		return "exit"

	case CallStackExhausted:
		return "call stack exhausted"

	case IndirectCallIndex:
		return "indirect call index out of bounds"

	case IndirectCallSignature:
		return "indirect call signature mismatch"

	case MemoryOutOfBounds:
		return "memory access out of bounds"

	case Unreachable:
		return "unreachable"

	case IntegerDivideByZero:
		return "integer divide by zero"

	case IntegerOverflow:
		return "integer overflow"

	default:
		return "unknown trap"
	}
}

func (id Id) Error() string {
	return "trap: " + id.String()
}
