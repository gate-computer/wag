package gen

import (
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/types"
)

type RegCategory uint8

const (
	RegCategoryInt   = RegCategory(0)
	RegCategoryFloat = RegCategory(1)
)

func TypeRegCategory(t types.T) RegCategory {
	return RegCategory(t.Category() - 1)
}

func RegCategoryInvalid(cat RegCategory) bool {
	return cat > RegCategoryFloat
}

func (cat RegCategory) String() string {
	switch cat {
	case RegCategoryInt:
		return "int"

	case RegCategoryFloat:
		return "float"

	default:
		return "<invalid register category>"
	}
}

func RegCategoryMask(cat RegCategory, callRegs *[]regs.R, available ...bool) (mask uint64) {
	for i, a := range available {
		if a {
			mask |= uint64(1) << (uint8(i<<1) + uint8(cat))
			*callRegs = append(*callRegs, regs.R(i))
		}
	}
	return
}

func RegMask(intMask, floatMask uint64) uint64 {
	return intMask | floatMask
}
