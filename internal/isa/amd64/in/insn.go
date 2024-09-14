// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

const (
	// Opcode bits of some instructions are located at this offset in the ModRM
	// byte (ModRO part) or a standalone opcode byte.
	opcodeBase = 3
)

const (
	// GP opcodes
	ADD     = RM(0x03)
	OR      = RM(0x0b)
	AND     = RM(0x23)
	SUB     = RM(0x2b)
	XOR     = RM(0x33)
	CMP     = RM(0x3b)
	CMOVB   = RM2(0x0f<<8 | 0x42)
	CMOVAE  = RM2(0x0f<<8 | 0x43)
	CMOVE   = RM2(0x0f<<8 | 0x44)
	CMOVNE  = RM2(0x0f<<8 | 0x45)
	CMOVBE  = RM2(0x0f<<8 | 0x46)
	CMOVA   = RM2(0x0f<<8 | 0x47)
	CMOVS   = RM2(0x0f<<8 | 0x48)
	CMOVP   = RM2(0x0f<<8 | 0x4a)
	CMOVL   = RM2(0x0f<<8 | 0x4c)
	CMOVGE  = RM2(0x0f<<8 | 0x4d)
	CMOVLE  = RM2(0x0f<<8 | 0x4e)
	CMOVG   = RM2(0x0f<<8 | 0x4f)
	PUSHo   = O(0x50)
	POPo    = O(0x58)
	MOVSXD  = RM(0x63) // I64 only
	PUSHi   = Ipush(0x6a)
	IMULi   = RMI(0x6b)
	JNOcb   = Db(0x71)
	JBcb    = Db(0x72)
	JAEcb   = Db(0x73)
	JEcb    = Db(0x74)
	JNEcb   = Db(0x75)
	JBEcb   = Db(0x76)
	JAcb    = Db(0x77)
	JScb    = Db(0x78)
	JPcb    = Db(0x7a)
	JLcb    = Db(0x7c)
	JGEcb   = Db(0x7d)
	JLEcb   = Db(0x7e)
	JGcb    = Db(0x7f)
	ADDi    = MI(0x81<<16 | 0x83<<8 | 0<<opcodeBase)
	ORi     = MI(0x81<<16 | 0x83<<8 | 1<<opcodeBase)
	ANDi    = MI(0x81<<16 | 0x83<<8 | 4<<opcodeBase)
	SUBi    = MI(0x81<<16 | 0x83<<8 | 5<<opcodeBase)
	XORi    = MI(0x81<<16 | 0x83<<8 | 6<<opcodeBase)
	CMPi    = MI(0x81<<16 | 0x83<<8 | 7<<opcodeBase)
	TEST8   = RMdata8(0x84) // MR opcode
	TEST    = RM(0x85)      // MR opcode
	MOV8mr  = RMdata8(0x88)
	MOV16mr = RMdata16(0x89)
	MOVmr   = RM(0x89) // RegReg is untested
	MOV     = RM(0x8b)
	LEA     = RM(0x8d)
	POP     = M(0x8f<<8 | 0<<opcodeBase)
	JBcd    = D2d(0x0f<<8 | 0x82)
	JAEcd   = D2d(0x0f<<8 | 0x83)
	JEcd    = D2d(0x0f<<8 | 0x84)
	JNEcd   = D2d(0x0f<<8 | 0x85)
	JBEcd   = D2d(0x0f<<8 | 0x86)
	JAcd    = D2d(0x0f<<8 | 0x87)
	JScd    = D2d(0x0f<<8 | 0x88)
	JPcd    = D2d(0x0f<<8 | 0x8a)
	JLcd    = D2d(0x0f<<8 | 0x8c)
	JGEcd   = D2d(0x0f<<8 | 0x8d)
	JLEcd   = D2d(0x0f<<8 | 0x8e)
	JGcd    = D2d(0x0f<<8 | 0x8f)
	PAUSE   = NPprefix(0x90)
	SETB    = Mex2(0x0f<<8 | 0x92)
	SETAE   = Mex2(0x0f<<8 | 0x93)
	SETE    = Mex2(0x0f<<8 | 0x94)
	SETNE   = Mex2(0x0f<<8 | 0x95)
	SETBE   = Mex2(0x0f<<8 | 0x96)
	SETA    = Mex2(0x0f<<8 | 0x97)
	SETS    = Mex2(0x0f<<8 | 0x98)
	SETP    = Mex2(0x0f<<8 | 0x9a)
	SETL    = Mex2(0x0f<<8 | 0x9c)
	SETGE   = Mex2(0x0f<<8 | 0x9d)
	SETLE   = Mex2(0x0f<<8 | 0x9e)
	SETG    = Mex2(0x0f<<8 | 0x9f)
	CDQ     = NP(0x99)
	IMUL    = RM2(0x0f<<8 | 0xaf)
	MOVZX8  = RMex2(0x0f<<8 | 0xb6)
	MOVZX16 = RM2(0x0f<<8 | 0xb7)
	MOV64i  = OI(0xb8)
	POPCNT  = RMprefix(0xf3<<8 | 0xb8)
	TZCNT   = RMprefix(0xf3<<8 | 0xbc)
	LZCNT   = RMprefix(0xf3<<8 | 0xbd)
	BSF     = RM2(0x0f<<8 | 0xbc)
	BSR     = RM2(0x0f<<8 | 0xbd)
	MOVSX8  = RMex2(0x0f<<8 | 0xbe)
	MOVSX16 = RM2(0x0f<<8 | 0xbf)
	ROLi    = MI(0xc1<<8 | 0<<opcodeBase)
	RORi    = MI(0xc1<<8 | 1<<opcodeBase)
	SHLi    = MI(0xc1<<8 | 4<<opcodeBase)
	SHRi    = MI(0xc1<<8 | 5<<opcodeBase)
	SARi    = MI(0xc1<<8 | 7<<opcodeBase)
	RET     = NP(0xc3)
	MOV8i   = MI8(0xc6<<8 | 0<<opcodeBase)
	MOV16i  = MI16(0xc7<<8 | 0<<opcodeBase)
	MOV32i  = MI32(0xc7<<8 | 0<<opcodeBase)
	MOVi    = MI(0xc7<<16 | 0<<opcodeBase)
	ROL     = M(0xd3<<8 | 0<<opcodeBase)
	ROR     = M(0xd3<<8 | 1<<opcodeBase)
	SHL     = M(0xd3<<8 | 4<<opcodeBase)
	SHR     = M(0xd3<<8 | 5<<opcodeBase)
	SAR     = M(0xd3<<8 | 7<<opcodeBase)
	LOOPcb  = Db(0xe2)
	CALLcd  = Dd(0xe8)
	JMPcd   = Dd(0xe9)
	JMPcb   = Db(0xeb)
	NEG     = M(0xf7<<8 | 3<<opcodeBase)
	DIV     = M(0xf7<<8 | 6<<opcodeBase)
	IDIV    = M(0xf7<<8 | 7<<opcodeBase)
	INC     = M(0xff<<8 | 0<<opcodeBase)
	DEC     = M(0xff<<8 | 1<<opcodeBase)
	PUSH    = M(0xff<<8 | 6<<opcodeBase)

	// GP opcode pairs
	JEc  = D12(JEcd)<<16 | D12(JEcb)
	JPc  = D12(JPcd)<<16 | D12(JPcb)
	JLEc = D12(JLEcd)<<16 | D12(JLEcb)

	// GP/SSE opcodes
	CVTSI2Sx  = RMscalar(0x2a)           // CVTSI2SS or CVTSI2SD
	CVTTSx2SI = RMscalar(0x2c)           // CVTTSS2SI or CVTTSD2SI
	MOVx      = RMprefix(0x66<<8 | 0x6e) // MOVD or MOVQ
	MOVxmr    = RMprefix(0x66<<8 | 0x7e) // register parameters reversed

	// SSE opcodes
	MOVSx   = RMscalar(0x10)  // MOVSS or MOVSD
	MOVSxmr = RMscalar(0x11)  // RegReg is redundant
	MOVAPx  = RMpacked(0x28)  // MOVAPS or MOVAPD
	UCOMISx = RMpacked(0x2e)  // UCOMISS or UCOMISD
	ROUNDSx = RMIscalar(0x3a) // ROUNDSS or ROUNDSD
	SQRTSx  = RMscalar(0x51)  // SQRTSS or SQRTSD
	ANDPx   = RMpacked(0x54)  // ANDPS or ANDPD
	ORPx    = RMpacked(0x56)  // ORPS or ORPD
	XORPx   = RMpacked(0x57)  // XORPS or XORPD
	ADDSx   = RMscalar(0x58)  // ADDSS or ADDSD
	MULSx   = RMscalar(0x59)  // MULSS or MULSD
	CVTS2Sx = RMscalar(0x5a)  // CVTS2SS or CVTS2SD
	SUBSx   = RMscalar(0x5c)  // SUBSS or SUBSD
	MINSx   = RMscalar(0x5d)  // MINSS or MINSD
	DIVSx   = RMscalar(0x5e)  // DIVSS or DIVSD
	MAXSx   = RMscalar(0x5f)  // MAXSS or MAXSD
	PXOR    = RMprefix(0x66<<8 | 0xef)
)

// Arithmetic logic instructions

type ALInsn byte

func (op ALInsn) Opcode() RM  { return RM(op | 0x3) }
func (ro ALInsn) OpcodeI() MI { return 0x81<<16 | 0x83<<8 | MI(ro) }

const (
	InsnAdd = ALInsn(0 << opcodeBase)
	InsnOr  = ALInsn(1 << opcodeBase)
	InsnAnd = ALInsn(4 << opcodeBase)
	InsnSub = ALInsn(5 << opcodeBase)
	InsnXor = ALInsn(6 << opcodeBase)
)

// Shift instructions

type ShiftInsn byte

const (
	InsnRotl = ShiftInsn(0 << opcodeBase)
	InsnRotr = ShiftInsn(1 << opcodeBase)
	InsnShl  = ShiftInsn(4 << opcodeBase)
	InsnShrU = ShiftInsn(5 << opcodeBase)
	InsnShrS = ShiftInsn(7 << opcodeBase)
)

func (ro ShiftInsn) Opcode() M   { return 0xd3<<8 | M(ro) }
func (ro ShiftInsn) OpcodeI() MI { return 0xc1<<8 | MI(ro) }

// Condition code instructions

type CCInsn byte

const (
	InsnLtU = CCInsn(0x2)
	InsnGeU = CCInsn(0x3)
	InsnEq  = CCInsn(0x4)
	InsnNe  = CCInsn(0x5)
	InsnLeU = CCInsn(0x6)
	InsnGtU = CCInsn(0x7)
	InsnLtS = CCInsn(0xc)
	InsnGeS = CCInsn(0xd)
	InsnLeS = CCInsn(0xe)
	InsnGtS = CCInsn(0xf)
)

func (nib CCInsn) SetccOpcode() Mex2 { return 0x0f<<8 | Mex2(0x90|nib) }
func (nib CCInsn) CmovccOpcode() RM2 { return 0x0f<<8 | RM2(0x40|nib) }
func (nib CCInsn) JccOpcodeCd() D2d  { return 0x0f<<8 | D2d(0x80|nib) }
func (nib CCInsn) JccOpcodeCb() Db   { return Db(0x70 | nib) }
func (cc CCInsn) JccOpcodeC() D12    { return D12(cc.JccOpcodeCd())<<16 | D12(cc.JccOpcodeCb()) }
