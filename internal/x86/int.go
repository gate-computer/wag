package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/types"
)

type rexPrefix byte

func (rex rexPrefix) writeTo(code gen.OpCoder, t types.T, ro, index, rmOrBase byte) {
	writeRexTo(code, byte(rex), ro, index, rmOrBase)
}

type rexSizePrefix struct{}

func (rexSizePrefix) writeTo(code gen.OpCoder, t types.T, ro, index, rmOrBase byte) {
	writeRexSizeTo(code, t, ro, index, rmOrBase)
}

type data16RexSizePrefix struct{}

func (data16RexSizePrefix) writeTo(code gen.OpCoder, t types.T, ro, index, rmOrBase byte) {
	code.WriteByte(0x66)
	writeRexSizeTo(code, t, ro, index, rmOrBase)
}

var (
	Rex           = rexPrefix(rex)
	RexW          = rexPrefix(rexW)
	RexSize       rexSizePrefix
	Data16RexSize data16RexSizePrefix
)

var (
	ConstF3RexSize = multiPrefix{constPrefix{0xf3}, RexSize}
)

var (
	Neg  = insnRexM{[]byte{0xf7}, 3}
	Mul  = insnRexM{[]byte{0xf7}, 4}
	Div  = insnRexM{[]byte{0xf7}, 6}
	Idiv = insnRexM{[]byte{0xf7}, 7}
	Inc  = insnRexM{[]byte{0xff}, 0}
	Dec  = insnRexM{[]byte{0xff}, 1}
	Rol  = insnRexM{[]byte{0xd3}, 0}
	Ror  = insnRexM{[]byte{0xd3}, 1}
	Shl  = insnRexM{[]byte{0xd3}, 4}
	Shr  = insnRexM{[]byte{0xd3}, 5}
	Sar  = insnRexM{[]byte{0xd3}, 7}

	Test    = insnPrefix{RexSize, []byte{0x85}, nil}
	Cmovb   = insnPrefix{RexSize, []byte{0x0f, 0x42}, nil}
	Cmovae  = insnPrefix{RexSize, []byte{0x0f, 0x43}, nil}
	Cmove   = insnPrefix{RexSize, []byte{0x0f, 0x44}, nil}
	Cmovne  = insnPrefix{RexSize, []byte{0x0f, 0x45}, nil}
	Cmovbe  = insnPrefix{RexSize, []byte{0x0f, 0x46}, nil}
	Cmova   = insnPrefix{RexSize, []byte{0x0f, 0x47}, nil}
	Cmovl   = insnPrefix{RexSize, []byte{0x0f, 0x4c}, nil}
	Cmovge  = insnPrefix{RexSize, []byte{0x0f, 0x4d}, nil}
	Cmovle  = insnPrefix{RexSize, []byte{0x0f, 0x4e}, nil}
	Cmovg   = insnPrefix{RexSize, []byte{0x0f, 0x4f}, nil}
	Movzx8  = insnPrefix{RexSize, []byte{0x0f, 0xb6}, nil}
	Movzx16 = insnPrefix{RexSize, []byte{0x0f, 0xb7}, nil}
	Bsf     = insnPrefix{RexSize, []byte{0x0f, 0xbc}, nil}
	Bsr     = insnPrefix{RexSize, []byte{0x0f, 0xbd}, nil}
	Movsx8  = insnPrefix{RexSize, []byte{0x0f, 0xbe}, nil}
	Movsx16 = insnPrefix{RexSize, []byte{0x0f, 0xbf}, nil}
	Movsxd  = insnPrefix{RexW, []byte{0x63}, nil} // variable rexR, rexX and rexB
	Popcnt  = insnPrefix{ConstF3RexSize, []byte{0x0f, 0xb8}, nil}

	Xchg = xchgInsn{
		insnRexO{0x90},
		insnPrefix{RexSize, []byte{0x87}, []byte{0x87}},
	}

	MovImm = insnPrefixMI{RexSize, 0, 0, 0xc7, 0}

	Add = binaryInsn{
		insnPrefix{RexSize, []byte{0x03}, nil},
		insnPrefixMI{RexSize, 0x83, 0, 0x81, 0},
	}
	Or = binaryInsn{
		insnPrefix{RexSize, []byte{0x0b}, nil},
		insnPrefixMI{RexSize, 0x83, 0, 0x81, 1},
	}
	And = binaryInsn{
		insnPrefix{RexSize, []byte{0x23}, nil},
		insnPrefixMI{RexSize, 0x83, 0, 0x81, 4},
	}
	Sub = binaryInsn{
		insnPrefix{RexSize, []byte{0x2b}, nil},
		insnPrefixMI{RexSize, 0x83, 0, 0x81, 5},
	}
	Xor = binaryInsn{
		insnPrefix{RexSize, []byte{0x33}, nil},
		insnPrefixMI{RexSize, 0x83, 0, 0x81, 6},
	}
	Cmp = binaryInsn{
		insnPrefix{RexSize, []byte{0x3b}, nil},
		insnPrefixMI{RexSize, 0x83, 0, 0x81, 7},
	}
	Mov8 = binaryInsn{
		insnPrefix{Rex, []byte{0x8a}, []byte{0x88}},
		insnPrefixMI{RexSize, 0xc6, 0, 0, 0},
	}
	Mov16 = binaryInsn{
		insnPrefix{Data16RexSize, []byte{0x8b}, []byte{0x89}},
		insnPrefixMI{Data16RexSize, 0, 0xc7, 0, 0},
	}
	Mov = binaryInsn{
		insnPrefix{RexSize, []byte{0x8b}, []byte{0x89}},
		MovImm,
	}

	Push = pushPopInsn{
		insnO{0x50},
		insnRexM{[]byte{0xff}, 6},
	}
	Pop = pushPopInsn{
		insnO{0x58},
		insnRexM{[]byte{0x8f}, 0},
	}

	RolImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 0},
		insnPrefixMI{RexSize, 0xc1, 0, 0, 0},
	}
	RorImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 1},
		insnPrefixMI{RexSize, 0xc1, 0, 0, 1},
	}
	ShlImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 4},
		insnPrefixMI{RexSize, 0xc1, 0, 0, 4},
	}
	ShrImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 5},
		insnPrefixMI{RexSize, 0xc1, 0, 0, 5},
	}
	SarImm = shiftImmInsn{
		insnRexM{[]byte{0xd1}, 7},
		insnPrefixMI{RexSize, 0xc1, 0, 0, 7},
	}

	MovImm64 = movImmInsn{
		MovImm,
		insnRexOI{0xb8},
	}
)

func isPowerOfTwo(value uint64) bool {
	return (value & (value - 1)) == 0
}

// log2 assumes that value isPowerOfTwo.
func log2(value uint64) (count uint8) {
	for {
		value >>= 1
		if value == 0 {
			return
		}
		count++
	}
}
