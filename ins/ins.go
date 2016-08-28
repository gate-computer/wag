package ins

import (
	"fmt"
)

type Add struct {
	Type      Type
	SourceReg byte
	TargetReg byte
}

func (x Add) String() string {
	return fmt.Sprintf("\tadd.%v\tr%d, r%d", x.Type, x.SourceReg, x.TargetReg)
}

type AddSP struct {
	Offset int
}

func (x AddSP) String() string {
	return fmt.Sprintf("\tadd\t#%d, sp", x.Offset)
}

type Br struct {
	Target *Stub
}

func (x Br) String() string {
	return fmt.Sprintf("\tbr\t.%p", x.Target)
}

type BrIfNot struct {
	Reg    byte
	Target *Stub
}

func (x BrIfNot) String() string {
	return fmt.Sprintf("\tbrifnot\tr%d, .%p", x.Reg, x.Target)
}

type Call struct {
	Target *Stub
}

func (x Call) String() string {
	return fmt.Sprintf("\tcall\t%s", x.Target.Name)
}

type Invalid struct{}

func (x Invalid) String() string {
	return "\tinvalid"
}

type Label struct {
	Stub *Stub
}

func (x Label) String() string {
	return fmt.Sprintf(".%p:", x.Stub)
}

type MovImmToReg struct {
	Type      Type
	SourceImm interface{}
	TargetReg byte
}

func (x MovImmToReg) String() string {
	return fmt.Sprintf("\tmov.%s\t#%v, r%d", x.Type, x.SourceImm, x.TargetReg)
}

type MovRegToReg struct {
	SourceReg byte
	TargetReg byte
}

func (x MovRegToReg) String() string {
	return fmt.Sprintf("\tmov\tr%d, r%d", x.SourceReg, x.TargetReg)
}

type MovVarToReg struct {
	SourceOffset int
	TargetReg    byte
}

func (x MovVarToReg) String() string {
	return fmt.Sprintf("\tmov\t%d(sp), r%d", x.SourceOffset, x.TargetReg)
}

type NE struct {
	Type       Type
	SourceReg  byte
	TargetReg  byte
	ScratchReg byte
}

func (x NE) String() string {
	return fmt.Sprintf("\tne.%s\tr%d, r%d", x.Type, x.SourceReg, x.TargetReg)
}

type Pop struct {
	TargetReg byte
}

func (x Pop) String() string {
	return fmt.Sprintf("\tpop\tr%d", x.TargetReg)
}

type Push struct {
	SourceReg byte
}

func (x Push) String() string {
	return fmt.Sprintf("\tpush\tr%d", x.SourceReg)
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
