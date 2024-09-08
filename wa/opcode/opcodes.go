// Copyright (c) 2024 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opcode

const (
	Unreachable       = Opcode(0x00)
	Nop               = Opcode(0x01)
	Block             = Opcode(0x02)
	Loop              = Opcode(0x03)
	If                = Opcode(0x04)
	Else              = Opcode(0x05)
	End               = Opcode(0x0b)
	Br                = Opcode(0x0c)
	BrIf              = Opcode(0x0d)
	BrTable           = Opcode(0x0e)
	Return            = Opcode(0x0f)
	Call              = Opcode(0x10)
	CallIndirect      = Opcode(0x11)
	Drop              = Opcode(0x1a)
	Select            = Opcode(0x1b)
	GetLocal          = Opcode(0x20)
	SetLocal          = Opcode(0x21)
	TeeLocal          = Opcode(0x22)
	GetGlobal         = Opcode(0x23)
	SetGlobal         = Opcode(0x24)
	I32Load           = Opcode(0x28)
	I64Load           = Opcode(0x29)
	F32Load           = Opcode(0x2a)
	F64Load           = Opcode(0x2b)
	I32Load8S         = Opcode(0x2c)
	I32Load8U         = Opcode(0x2d)
	I32Load16S        = Opcode(0x2e)
	I32Load16U        = Opcode(0x2f)
	I64Load8S         = Opcode(0x30)
	I64Load8U         = Opcode(0x31)
	I64Load16S        = Opcode(0x32)
	I64Load16U        = Opcode(0x33)
	I64Load32S        = Opcode(0x34)
	I64Load32U        = Opcode(0x35)
	I32Store          = Opcode(0x36)
	I64Store          = Opcode(0x37)
	F32Store          = Opcode(0x38)
	F64Store          = Opcode(0x39)
	I32Store8         = Opcode(0x3a)
	I32Store16        = Opcode(0x3b)
	I64Store8         = Opcode(0x3c)
	I64Store16        = Opcode(0x3d)
	I64Store32        = Opcode(0x3e)
	CurrentMemory     = Opcode(0x3f)
	GrowMemory        = Opcode(0x40)
	I32Const          = Opcode(0x41)
	I64Const          = Opcode(0x42)
	F32Const          = Opcode(0x43)
	F64Const          = Opcode(0x44)
	I32Eqz            = Opcode(0x45)
	I32Eq             = Opcode(0x46)
	I32Ne             = Opcode(0x47)
	I32LtS            = Opcode(0x48)
	I32LtU            = Opcode(0x49)
	I32GtS            = Opcode(0x4a)
	I32GtU            = Opcode(0x4b)
	I32LeS            = Opcode(0x4c)
	I32LeU            = Opcode(0x4d)
	I32GeS            = Opcode(0x4e)
	I32GeU            = Opcode(0x4f)
	I64Eqz            = Opcode(0x50)
	I64Eq             = Opcode(0x51)
	I64Ne             = Opcode(0x52)
	I64LtS            = Opcode(0x53)
	I64LtU            = Opcode(0x54)
	I64GtS            = Opcode(0x55)
	I64GtU            = Opcode(0x56)
	I64LeS            = Opcode(0x57)
	I64LeU            = Opcode(0x58)
	I64GeS            = Opcode(0x59)
	I64GeU            = Opcode(0x5a)
	F32Eq             = Opcode(0x5b)
	F32Ne             = Opcode(0x5c)
	F32Lt             = Opcode(0x5d)
	F32Gt             = Opcode(0x5e)
	F32Le             = Opcode(0x5f)
	F32Ge             = Opcode(0x60)
	F64Eq             = Opcode(0x61)
	F64Ne             = Opcode(0x62)
	F64Lt             = Opcode(0x63)
	F64Gt             = Opcode(0x64)
	F64Le             = Opcode(0x65)
	F64Ge             = Opcode(0x66)
	I32Clz            = Opcode(0x67)
	I32Ctz            = Opcode(0x68)
	I32Popcnt         = Opcode(0x69)
	I32Add            = Opcode(0x6a)
	I32Sub            = Opcode(0x6b)
	I32Mul            = Opcode(0x6c)
	I32DivS           = Opcode(0x6d)
	I32DivU           = Opcode(0x6e)
	I32RemS           = Opcode(0x6f)
	I32RemU           = Opcode(0x70)
	I32And            = Opcode(0x71)
	I32Or             = Opcode(0x72)
	I32Xor            = Opcode(0x73)
	I32Shl            = Opcode(0x74)
	I32ShrS           = Opcode(0x75)
	I32ShrU           = Opcode(0x76)
	I32Rotl           = Opcode(0x77)
	I32Rotr           = Opcode(0x78)
	I64Clz            = Opcode(0x79)
	I64Ctz            = Opcode(0x7a)
	I64Popcnt         = Opcode(0x7b)
	I64Add            = Opcode(0x7c)
	I64Sub            = Opcode(0x7d)
	I64Mul            = Opcode(0x7e)
	I64DivS           = Opcode(0x7f)
	I64DivU           = Opcode(0x80)
	I64RemS           = Opcode(0x81)
	I64RemU           = Opcode(0x82)
	I64And            = Opcode(0x83)
	I64Or             = Opcode(0x84)
	I64Xor            = Opcode(0x85)
	I64Shl            = Opcode(0x86)
	I64ShrS           = Opcode(0x87)
	I64ShrU           = Opcode(0x88)
	I64Rotl           = Opcode(0x89)
	I64Rotr           = Opcode(0x8a)
	F32Abs            = Opcode(0x8b)
	F32Neg            = Opcode(0x8c)
	F32Ceil           = Opcode(0x8d)
	F32Floor          = Opcode(0x8e)
	F32Trunc          = Opcode(0x8f)
	F32Nearest        = Opcode(0x90)
	F32Sqrt           = Opcode(0x91)
	F32Add            = Opcode(0x92)
	F32Sub            = Opcode(0x93)
	F32Mul            = Opcode(0x94)
	F32Div            = Opcode(0x95)
	F32Min            = Opcode(0x96)
	F32Max            = Opcode(0x97)
	F32Copysign       = Opcode(0x98)
	F64Abs            = Opcode(0x99)
	F64Neg            = Opcode(0x9a)
	F64Ceil           = Opcode(0x9b)
	F64Floor          = Opcode(0x9c)
	F64Trunc          = Opcode(0x9d)
	F64Nearest        = Opcode(0x9e)
	F64Sqrt           = Opcode(0x9f)
	F64Add            = Opcode(0xa0)
	F64Sub            = Opcode(0xa1)
	F64Mul            = Opcode(0xa2)
	F64Div            = Opcode(0xa3)
	F64Min            = Opcode(0xa4)
	F64Max            = Opcode(0xa5)
	F64Copysign       = Opcode(0xa6)
	I32WrapI64        = Opcode(0xa7)
	I32TruncSF32      = Opcode(0xa8)
	I32TruncUF32      = Opcode(0xa9)
	I32TruncSF64      = Opcode(0xaa)
	I32TruncUF64      = Opcode(0xab)
	I64ExtendSI32     = Opcode(0xac)
	I64ExtendUI32     = Opcode(0xad)
	I64TruncSF32      = Opcode(0xae)
	I64TruncUF32      = Opcode(0xaf)
	I64TruncSF64      = Opcode(0xb0)
	I64TruncUF64      = Opcode(0xb1)
	F32ConvertSI32    = Opcode(0xb2)
	F32ConvertUI32    = Opcode(0xb3)
	F32ConvertSI64    = Opcode(0xb4)
	F32ConvertUI64    = Opcode(0xb5)
	F32DemoteF64      = Opcode(0xb6)
	F64ConvertSI32    = Opcode(0xb7)
	F64ConvertUI32    = Opcode(0xb8)
	F64ConvertSI64    = Opcode(0xb9)
	F64ConvertUI64    = Opcode(0xba)
	F64PromoteF32     = Opcode(0xbb)
	I32ReinterpretF32 = Opcode(0xbc)
	I64ReinterpretF64 = Opcode(0xbd)
	F32ReinterpretI32 = Opcode(0xbe)
	F64ReinterpretI64 = Opcode(0xbf)
	MiscPrefix        = Opcode(0xfc)
)

var strings = [256]string{
	Unreachable:       "unreachable",
	Nop:               "nop",
	Block:             "block",
	Loop:              "loop",
	If:                "if",
	Else:              "else",
	End:               "end",
	Br:                "br",
	BrIf:              "br_if",
	BrTable:           "br_table",
	Return:            "return",
	Call:              "call",
	CallIndirect:      "call_indirect",
	Drop:              "drop",
	Select:            "select",
	GetLocal:          "get_local",
	SetLocal:          "set_local",
	TeeLocal:          "tee_local",
	GetGlobal:         "get_global",
	SetGlobal:         "set_global",
	I32Load:           "i32.load",
	I64Load:           "i64.load",
	F32Load:           "f32.load",
	F64Load:           "f64.load",
	I32Load8S:         "i32.load8_s",
	I32Load8U:         "i32.load8_u",
	I32Load16S:        "i32.load16_s",
	I32Load16U:        "i32.load16_u",
	I64Load8S:         "i64.load8_s",
	I64Load8U:         "i64.load8_u",
	I64Load16S:        "i64.load16_s",
	I64Load16U:        "i64.load16_u",
	I64Load32S:        "i64.load32_s",
	I64Load32U:        "i64.load32_u",
	I32Store:          "i32.store",
	I64Store:          "i64.store",
	F32Store:          "f32.store",
	F64Store:          "f64.store",
	I32Store8:         "i32.store8",
	I32Store16:        "i32.store16",
	I64Store8:         "i64.store8",
	I64Store16:        "i64.store16",
	I64Store32:        "i64.store32",
	CurrentMemory:     "current_memory",
	GrowMemory:        "grow_memory",
	I32Const:          "i32.const",
	I64Const:          "i64.const",
	F32Const:          "f32.const",
	F64Const:          "f64.const",
	I32Eqz:            "i32.eqz",
	I32Eq:             "i32.eq",
	I32Ne:             "i32.ne",
	I32LtS:            "i32.lt_s",
	I32LtU:            "i32.lt_u",
	I32GtS:            "i32.gt_s",
	I32GtU:            "i32.gt_u",
	I32LeS:            "i32.le_s",
	I32LeU:            "i32.le_u",
	I32GeS:            "i32.ge_s",
	I32GeU:            "i32.ge_u",
	I64Eqz:            "i64.eqz",
	I64Eq:             "i64.eq",
	I64Ne:             "i64.ne",
	I64LtS:            "i64.lt_s",
	I64LtU:            "i64.lt_u",
	I64GtS:            "i64.gt_s",
	I64GtU:            "i64.gt_u",
	I64LeS:            "i64.le_s",
	I64LeU:            "i64.le_u",
	I64GeS:            "i64.ge_s",
	I64GeU:            "i64.ge_u",
	F32Eq:             "f32.eq",
	F32Ne:             "f32.ne",
	F32Lt:             "f32.lt",
	F32Gt:             "f32.gt",
	F32Le:             "f32.le",
	F32Ge:             "f32.ge",
	F64Eq:             "f64.eq",
	F64Ne:             "f64.ne",
	F64Lt:             "f64.lt",
	F64Gt:             "f64.gt",
	F64Le:             "f64.le",
	F64Ge:             "f64.ge",
	I32Clz:            "i32.clz",
	I32Ctz:            "i32.ctz",
	I32Popcnt:         "i32.popcnt",
	I32Add:            "i32.add",
	I32Sub:            "i32.sub",
	I32Mul:            "i32.mul",
	I32DivS:           "i32.div_s",
	I32DivU:           "i32.div_u",
	I32RemS:           "i32.rem_s",
	I32RemU:           "i32.rem_u",
	I32And:            "i32.and",
	I32Or:             "i32.or",
	I32Xor:            "i32.xor",
	I32Shl:            "i32.shl",
	I32ShrS:           "i32.shr_s",
	I32ShrU:           "i32.shr_u",
	I32Rotl:           "i32.rotl",
	I32Rotr:           "i32.rotr",
	I64Clz:            "i64.clz",
	I64Ctz:            "i64.ctz",
	I64Popcnt:         "i64.popcnt",
	I64Add:            "i64.add",
	I64Sub:            "i64.sub",
	I64Mul:            "i64.mul",
	I64DivS:           "i64.div_s",
	I64DivU:           "i64.div_u",
	I64RemS:           "i64.rem_s",
	I64RemU:           "i64.rem_u",
	I64And:            "i64.and",
	I64Or:             "i64.or",
	I64Xor:            "i64.xor",
	I64Shl:            "i64.shl",
	I64ShrS:           "i64.shr_s",
	I64ShrU:           "i64.shr_u",
	I64Rotl:           "i64.rotl",
	I64Rotr:           "i64.rotr",
	F32Abs:            "f32.abs",
	F32Neg:            "f32.neg",
	F32Ceil:           "f32.ceil",
	F32Floor:          "f32.floor",
	F32Trunc:          "f32.trunc",
	F32Nearest:        "f32.nearest",
	F32Sqrt:           "f32.sqrt",
	F32Add:            "f32.add",
	F32Sub:            "f32.sub",
	F32Mul:            "f32.mul",
	F32Div:            "f32.div",
	F32Min:            "f32.min",
	F32Max:            "f32.max",
	F32Copysign:       "f32.copysign",
	F64Abs:            "f64.abs",
	F64Neg:            "f64.neg",
	F64Ceil:           "f64.ceil",
	F64Floor:          "f64.floor",
	F64Trunc:          "f64.trunc",
	F64Nearest:        "f64.nearest",
	F64Sqrt:           "f64.sqrt",
	F64Add:            "f64.add",
	F64Sub:            "f64.sub",
	F64Mul:            "f64.mul",
	F64Div:            "f64.div",
	F64Min:            "f64.min",
	F64Max:            "f64.max",
	F64Copysign:       "f64.copysign",
	I32WrapI64:        "i32.wrap/i64",
	I32TruncSF32:      "i32.trunc_s/f32",
	I32TruncUF32:      "i32.trunc_u/f32",
	I32TruncSF64:      "i32.trunc_s/f64",
	I32TruncUF64:      "i32.trunc_u/f64",
	I64ExtendSI32:     "i64.extend_s/i32",
	I64ExtendUI32:     "i64.extend_u/i32",
	I64TruncSF32:      "i64.trunc_s/f32",
	I64TruncUF32:      "i64.trunc_u/f32",
	I64TruncSF64:      "i64.trunc_s/f64",
	I64TruncUF64:      "i64.trunc_u/f64",
	F32ConvertSI32:    "f32.convert_s/i32",
	F32ConvertUI32:    "f32.convert_u/i32",
	F32ConvertSI64:    "f32.convert_s/i64",
	F32ConvertUI64:    "f32.convert_u/i64",
	F32DemoteF64:      "f32.demote/f64",
	F64ConvertSI32:    "f64.convert_s/i32",
	F64ConvertUI32:    "f64.convert_u/i32",
	F64ConvertSI64:    "f64.convert_s/i64",
	F64ConvertUI64:    "f64.convert_u/i64",
	F64PromoteF32:     "f64.promote/f32",
	I32ReinterpretF32: "i32.reinterpret/f32",
	I64ReinterpretF64: "i64.reinterpret/f64",
	F32ReinterpretI32: "f32.reinterpret/i32",
	F64ReinterpretI64: "f64.reinterpret/i64",
	MiscPrefix:        "misc",
}

const (
	I32TruncSatSF32 = MiscOpcode(0x00)
	I32TruncSatUF32 = MiscOpcode(0x01)
	I32TruncSatSF64 = MiscOpcode(0x02)
	I32TruncSatUF64 = MiscOpcode(0x03)
	I64TruncSatSF32 = MiscOpcode(0x04)
	I64TruncSatUF32 = MiscOpcode(0x05)
	I64TruncSatSF64 = MiscOpcode(0x06)
	I64TruncSatUF64 = MiscOpcode(0x07)
)

var miscStrings = [...]string{
	I32TruncSatSF32: "i32.trunc_sat_s/f32",
	I32TruncSatUF32: "i32.trunc_sat_u/f32",
	I32TruncSatSF64: "i32.trunc_sat_s/f64",
	I32TruncSatUF64: "i32.trunc_sat_u/f64",
	I64TruncSatSF32: "i64.trunc_sat_s/f32",
	I64TruncSatUF32: "i64.trunc_sat_u/f32",
	I64TruncSatSF64: "i64.trunc_sat_s/f64",
	I64TruncSatUF64: "i64.trunc_sat_u/f64",
}
