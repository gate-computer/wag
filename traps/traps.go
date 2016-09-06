package traps

type Id int

const (
	IndirectCallIndex = Id(iota)
	IndirectCallSignature
)

func (id Id) String() string {
	switch id {
	case IndirectCallIndex:
		return "indirect call index out of bounds"

	case IndirectCallSignature:
		return "indirect call signature mismatch"

	default:
		return "unknown trap"
	}
}
