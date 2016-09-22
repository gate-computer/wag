package traps

type Id int

const (
	DivideByZero = Id(iota + 1)
	CallStackExhausted
	IndirectCallIndex
	IndirectCallSignature
	MemoryOutOfBounds
	Unreachable
)

func (id Id) String() string {
	switch id {
	case DivideByZero:
		return "divide by zero"

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

	default:
		return "unknown trap"
	}
}

func (id Id) Error() string {
	return "trap: " + id.String()
}
