package ins

import (
	"fmt"
)

type Push struct {
	SourceReg byte
}

func (x Push) String() string {
	return fmt.Sprintf("\tpush\tr%d", x.SourceReg)
}

type Pop struct {
	TargetReg byte
}

func (x Pop) String() string {
	return fmt.Sprintf("\tpop\tr%d", x.TargetReg)
}

type MovRegToReg struct {
	SourceReg byte
	TargetReg byte
}

func (x MovRegToReg) String() string {
	return fmt.Sprintf("\tmov\tr%d, r%d", x.SourceReg, x.TargetReg)
}

type MovImmToReg struct {
	Type      Type
	SourceImm interface{}
	TargetReg byte
}

func (x MovImmToReg) String() string {
	return fmt.Sprintf("\tmov.%v\t#%v, r%d", x.Type, x.SourceImm, x.TargetReg)
}

type MovVarToReg struct {
	SourceOffset int
	TargetReg    byte
}

func (x MovVarToReg) String() string {
	return fmt.Sprintf("\tmov\t(sp+%d), r%d", x.SourceOffset, x.TargetReg)
}

type Add struct {
	Type      Type
	SourceReg byte
	TargetReg byte
}

func (x Add) String() string {
	return fmt.Sprintf("\tadd.%v\tr%d, r%d", x.Type, x.SourceReg, x.TargetReg)
}

type Call struct {
	Function *Stub
}

func (x Call) String() string {
	return fmt.Sprintf("\tcall\t%s", x.Function.Name)
}

type Ret struct{}

func (x Ret) String() string {
	return "\tret"
}

type XOR struct {
	SourceReg byte
	TargetReg byte
}

func (x XOR) String() string {
	return fmt.Sprintf("\txor\tr%d, r%d", x.SourceReg, x.TargetReg)
}
