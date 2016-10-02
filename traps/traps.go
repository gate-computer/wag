package traps

type Id int

const (
	Exit = Id(iota)
	MissingFunction

	CallStackExhausted
	IndirectCallIndex
	IndirectCallSignature
	MemoryOutOfBounds
	Unreachable
	IntegerDivideByZero
	IntegerOverflow

	NumTraps
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
		return "out of bounds memory access"

	case Unreachable:
		return "unreachable"

	case IntegerDivideByZero:
		return "integer divide by zero"

	case IntegerOverflow:
		return "integer overflow"

	case MissingFunction:
		return "missing function"

	default:
		return "unknown trap"
	}
}

func (id Id) Error() string {
	return "trap: " + id.String()
}
