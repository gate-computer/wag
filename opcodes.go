package wag

import (
	"github.com/tsavola/wag/internal/opers"
	"github.com/tsavola/wag/types"
)

const (
	opcodeUnreachable       = opcode(0x00)
	opcodeBlock             = opcode(0x01)
	opcodeLoop              = opcode(0x02)
	opcodeIf                = opcode(0x03)
	opcodeElse              = opcode(0x04)
	opcodeSelect            = opcode(0x05)
	opcodeBr                = opcode(0x06)
	opcodeBrIf              = opcode(0x07)
	opcodeBrTable           = opcode(0x08)
	opcodeReturn            = opcode(0x09)
	opcodeNop               = opcode(0x0a)
	opcodeDrop              = opcode(0x0b)
	opcodeEnd               = opcode(0x0f)
	opcodeI32Const          = opcode(0x10)
	opcodeI64Const          = opcode(0x11)
	opcodeF64Const          = opcode(0x12)
	opcodeF32Const          = opcode(0x13)
	opcodeGetLocal          = opcode(0x14)
	opcodeSetLocal          = opcode(0x15)
	opcodeCall              = opcode(0x16)
	opcodeCallIndirect      = opcode(0x17)
	opcodeTeeLocal          = opcode(0x19)
	opcodeI32Load8S         = opcode(0x20)
	opcodeI32Load8U         = opcode(0x21)
	opcodeI32Load16S        = opcode(0x22)
	opcodeI32Load16U        = opcode(0x23)
	opcodeI64Load8S         = opcode(0x24)
	opcodeI64Load8U         = opcode(0x25)
	opcodeI64Load16S        = opcode(0x26)
	opcodeI64Load16U        = opcode(0x27)
	opcodeI64Load32S        = opcode(0x28)
	opcodeI64Load32U        = opcode(0x29)
	opcodeI32Load           = opcode(0x2a)
	opcodeI64Load           = opcode(0x2b)
	opcodeF32Load           = opcode(0x2c)
	opcodeF64Load           = opcode(0x2d)
	opcodeI32Store8         = opcode(0x2e)
	opcodeI32Store16        = opcode(0x2f)
	opcodeI64Store8         = opcode(0x30)
	opcodeI64Store16        = opcode(0x31)
	opcodeI64Store32        = opcode(0x32)
	opcodeI32Store          = opcode(0x33)
	opcodeI64Store          = opcode(0x34)
	opcodeF32Store          = opcode(0x35)
	opcodeF64Store          = opcode(0x36)
	opcodeGrowMemory        = opcode(0x39)
	opcodeCurrentMemory     = opcode(0x3b)
	opcodeI32Add            = opcode(0x40)
	opcodeI32Sub            = opcode(0x41)
	opcodeI32Mul            = opcode(0x42)
	opcodeI32DivS           = opcode(0x43)
	opcodeI32DivU           = opcode(0x44)
	opcodeI32RemS           = opcode(0x45)
	opcodeI32RemU           = opcode(0x46)
	opcodeI32And            = opcode(0x47)
	opcodeI32Or             = opcode(0x48)
	opcodeI32Xor            = opcode(0x49)
	opcodeI32Shl            = opcode(0x4a)
	opcodeI32ShrU           = opcode(0x4b)
	opcodeI32ShrS           = opcode(0x4c)
	opcodeI32Eq             = opcode(0x4d)
	opcodeI32Ne             = opcode(0x4e)
	opcodeI32LtS            = opcode(0x4f)
	opcodeI32LeS            = opcode(0x50)
	opcodeI32LtU            = opcode(0x51)
	opcodeI32LeU            = opcode(0x52)
	opcodeI32GtS            = opcode(0x53)
	opcodeI32GeS            = opcode(0x54)
	opcodeI32GtU            = opcode(0x55)
	opcodeI32GeU            = opcode(0x56)
	opcodeI32Clz            = opcode(0x57)
	opcodeI32Ctz            = opcode(0x58)
	opcodeI32Popcnt         = opcode(0x59)
	opcodeI32Eqz            = opcode(0x5a)
	opcodeI64Add            = opcode(0x5b)
	opcodeI64Sub            = opcode(0x5c)
	opcodeI64Mul            = opcode(0x5d)
	opcodeI64DivS           = opcode(0x5e)
	opcodeI64DivU           = opcode(0x5f)
	opcodeI64RemS           = opcode(0x60)
	opcodeI64RemU           = opcode(0x61)
	opcodeI64And            = opcode(0x62)
	opcodeI64Or             = opcode(0x63)
	opcodeI64Xor            = opcode(0x64)
	opcodeI64Shl            = opcode(0x65)
	opcodeI64ShrU           = opcode(0x66)
	opcodeI64ShrS           = opcode(0x67)
	opcodeI64Eq             = opcode(0x68)
	opcodeI64Ne             = opcode(0x69)
	opcodeI64LtS            = opcode(0x6a)
	opcodeI64LeS            = opcode(0x6b)
	opcodeI64LtU            = opcode(0x6c)
	opcodeI64LeU            = opcode(0x6d)
	opcodeI64GtS            = opcode(0x6e)
	opcodeI64GeS            = opcode(0x6f)
	opcodeI64GtU            = opcode(0x70)
	opcodeI64GeU            = opcode(0x71)
	opcodeI64Clz            = opcode(0x72)
	opcodeI64Ctz            = opcode(0x73)
	opcodeI64Popcnt         = opcode(0x74)
	opcodeF32Add            = opcode(0x75)
	opcodeF32Sub            = opcode(0x76)
	opcodeF32Mul            = opcode(0x77)
	opcodeF32Div            = opcode(0x78)
	opcodeF32Min            = opcode(0x79)
	opcodeF32Max            = opcode(0x7a)
	opcodeF32Abs            = opcode(0x7b)
	opcodeF32Neg            = opcode(0x7c)
	opcodeF32Copysign       = opcode(0x7d)
	opcodeF32Ceil           = opcode(0x7e)
	opcodeF32Floor          = opcode(0x7f)
	opcodeF32Trunc          = opcode(0x80)
	opcodeF32Nearest        = opcode(0x81)
	opcodeF32Sqrt           = opcode(0x82)
	opcodeF32Eq             = opcode(0x83)
	opcodeF32Ne             = opcode(0x84)
	opcodeF32Lt             = opcode(0x85)
	opcodeF32Le             = opcode(0x86)
	opcodeF32Gt             = opcode(0x87)
	opcodeF32Ge             = opcode(0x88)
	opcodeF64Add            = opcode(0x89)
	opcodeF64Sub            = opcode(0x8a)
	opcodeF64Mul            = opcode(0x8b)
	opcodeF64Div            = opcode(0x8c)
	opcodeF64Min            = opcode(0x8d)
	opcodeF64Max            = opcode(0x8e)
	opcodeF64Abs            = opcode(0x8f)
	opcodeF64Neg            = opcode(0x90)
	opcodeF64Copysign       = opcode(0x91)
	opcodeF64Ceil           = opcode(0x92)
	opcodeF64Floor          = opcode(0x93)
	opcodeF64Trunc          = opcode(0x94)
	opcodeF64Nearest        = opcode(0x95)
	opcodeF64Sqrt           = opcode(0x96)
	opcodeF64Eq             = opcode(0x97)
	opcodeF64Ne             = opcode(0x98)
	opcodeF64Lt             = opcode(0x99)
	opcodeF64Le             = opcode(0x9a)
	opcodeF64Gt             = opcode(0x9b)
	opcodeF64Ge             = opcode(0x9c)
	opcodeI32TruncSF32      = opcode(0x9d)
	opcodeI32TruncSF64      = opcode(0x9e)
	opcodeI32TruncUF32      = opcode(0x9f)
	opcodeI32TruncUF64      = opcode(0xa0)
	opcodeI32WrapI64        = opcode(0xa1)
	opcodeI64TruncSF32      = opcode(0xa2)
	opcodeI64TruncSF64      = opcode(0xa3)
	opcodeI64TruncUF32      = opcode(0xa4)
	opcodeI64TruncUF64      = opcode(0xa5)
	opcodeI64ExtendSI32     = opcode(0xa6)
	opcodeI64ExtendUI32     = opcode(0xa7)
	opcodeF32ConvertSI32    = opcode(0xa8)
	opcodeF32ConvertUI32    = opcode(0xa9)
	opcodeF32ConvertSI64    = opcode(0xaa)
	opcodeF32ConvertUI64    = opcode(0xab)
	opcodeF32DemoteF64      = opcode(0xac)
	opcodeF32ReinterpretI32 = opcode(0xad)
	opcodeF64ConvertSI32    = opcode(0xae)
	opcodeF64ConvertUI32    = opcode(0xaf)
	opcodeF64ConvertSI64    = opcode(0xb0)
	opcodeF64ConvertUI64    = opcode(0xb1)
	opcodeF64PromoteF32     = opcode(0xb2)
	opcodeF64ReinterpretI64 = opcode(0xb3)
	opcodeI32ReinterpretF32 = opcode(0xb4)
	opcodeI64ReinterpretF64 = opcode(0xb5)
	opcodeI32Rotr           = opcode(0xb6)
	opcodeI32Rotl           = opcode(0xb7)
	opcodeI64Rotr           = opcode(0xb8)
	opcodeI64Rotl           = opcode(0xb9)
	opcodeI64Eqz            = opcode(0xba)
	opcodeGetGlobal         = opcode(0xbb)
	opcodeSetGlobal         = opcode(0xbc)
)

var opcodeStrings = [256]string{
	opcodeUnreachable:       "unreachable",
	opcodeBlock:             "block",
	opcodeLoop:              "loop",
	opcodeIf:                "if",
	opcodeElse:              "else",
	opcodeSelect:            "select",
	opcodeBr:                "br",
	opcodeBrIf:              "br_if",
	opcodeBrTable:           "br_table",
	opcodeReturn:            "return",
	opcodeNop:               "nop",
	opcodeDrop:              "drop",
	opcodeEnd:               "end",
	opcodeI32Const:          "i32.const",
	opcodeI64Const:          "i64.const",
	opcodeF64Const:          "f64.const",
	opcodeF32Const:          "f32.const",
	opcodeGetLocal:          "get_local",
	opcodeSetLocal:          "set_local",
	opcodeCall:              "call",
	opcodeCallIndirect:      "call_indirect",
	opcodeTeeLocal:          "tee_local",
	opcodeI32Load8S:         "i32.load8_s",
	opcodeI32Load8U:         "i32.load8_u",
	opcodeI32Load16S:        "i32.load16_s",
	opcodeI32Load16U:        "i32.load16_u",
	opcodeI64Load8S:         "i64.load8_s",
	opcodeI64Load8U:         "i64.load8_u",
	opcodeI64Load16S:        "i64.load16_s",
	opcodeI64Load16U:        "i64.load16_u",
	opcodeI64Load32S:        "i64.load32_s",
	opcodeI64Load32U:        "i64.load32_u",
	opcodeI32Load:           "i32.load",
	opcodeI64Load:           "i64.load",
	opcodeF32Load:           "f32.load",
	opcodeF64Load:           "f64.load",
	opcodeI32Store8:         "i32.store8",
	opcodeI32Store16:        "i32.store16",
	opcodeI64Store8:         "i64.store8",
	opcodeI64Store16:        "i64.store16",
	opcodeI64Store32:        "i64.store32",
	opcodeI32Store:          "i32.store",
	opcodeI64Store:          "i64.store",
	opcodeF32Store:          "f32.store",
	opcodeF64Store:          "f64.store",
	opcodeGrowMemory:        "grow_memory",
	opcodeCurrentMemory:     "current_memory",
	opcodeI32Add:            "i32.add",
	opcodeI32Sub:            "i32.sub",
	opcodeI32Mul:            "i32.mul",
	opcodeI32DivS:           "i32.div_s",
	opcodeI32DivU:           "i32.div_u",
	opcodeI32RemS:           "i32.rem_s",
	opcodeI32RemU:           "i32.rem_u",
	opcodeI32And:            "i32.and",
	opcodeI32Or:             "i32.or",
	opcodeI32Xor:            "i32.xor",
	opcodeI32Shl:            "i32.shl",
	opcodeI32ShrU:           "i32.shr_u",
	opcodeI32ShrS:           "i32.shr_s",
	opcodeI32Eq:             "i32.eq",
	opcodeI32Ne:             "i32.ne",
	opcodeI32LtS:            "i32.lt_s",
	opcodeI32LeS:            "i32.le_s",
	opcodeI32LtU:            "i32.lt_u",
	opcodeI32LeU:            "i32.le_u",
	opcodeI32GtS:            "i32.gt_s",
	opcodeI32GeS:            "i32.ge_s",
	opcodeI32GtU:            "i32.gt_u",
	opcodeI32GeU:            "i32.ge_u",
	opcodeI32Clz:            "i32.clz",
	opcodeI32Ctz:            "i32.ctz",
	opcodeI32Popcnt:         "i32.popcnt",
	opcodeI32Eqz:            "i32.eqz",
	opcodeI64Add:            "i64.add",
	opcodeI64Sub:            "i64.sub",
	opcodeI64Mul:            "i64.mul",
	opcodeI64DivS:           "i64.div_s",
	opcodeI64DivU:           "i64.div_u",
	opcodeI64RemS:           "i64.rem_s",
	opcodeI64RemU:           "i64.rem_u",
	opcodeI64And:            "i64.and",
	opcodeI64Or:             "i64.or",
	opcodeI64Xor:            "i64.xor",
	opcodeI64Shl:            "i64.shl",
	opcodeI64ShrU:           "i64.shr_u",
	opcodeI64ShrS:           "i64.shr_s",
	opcodeI64Eq:             "i64.eq",
	opcodeI64Ne:             "i64.ne",
	opcodeI64LtS:            "i64.lt_s",
	opcodeI64LeS:            "i64.le_s",
	opcodeI64LtU:            "i64.lt_u",
	opcodeI64LeU:            "i64.le_u",
	opcodeI64GtS:            "i64.gt_s",
	opcodeI64GeS:            "i64.ge_s",
	opcodeI64GtU:            "i64.gt_u",
	opcodeI64GeU:            "i64.ge_u",
	opcodeI64Clz:            "i64.clz",
	opcodeI64Ctz:            "i64.ctz",
	opcodeI64Popcnt:         "i64.popcnt",
	opcodeF32Add:            "f32.add",
	opcodeF32Sub:            "f32.sub",
	opcodeF32Mul:            "f32.mul",
	opcodeF32Div:            "f32.div",
	opcodeF32Min:            "f32.min",
	opcodeF32Max:            "f32.max",
	opcodeF32Abs:            "f32.abs",
	opcodeF32Neg:            "f32.neg",
	opcodeF32Copysign:       "f32.copysign",
	opcodeF32Ceil:           "f32.ceil",
	opcodeF32Floor:          "f32.floor",
	opcodeF32Trunc:          "f32.trunc",
	opcodeF32Nearest:        "f32.nearest",
	opcodeF32Sqrt:           "f32.sqrt",
	opcodeF32Eq:             "f32.eq",
	opcodeF32Ne:             "f32.ne",
	opcodeF32Lt:             "f32.lt",
	opcodeF32Le:             "f32.le",
	opcodeF32Gt:             "f32.gt",
	opcodeF32Ge:             "f32.ge",
	opcodeF64Add:            "f64.add",
	opcodeF64Sub:            "f64.sub",
	opcodeF64Mul:            "f64.mul",
	opcodeF64Div:            "f64.div",
	opcodeF64Min:            "f64.min",
	opcodeF64Max:            "f64.max",
	opcodeF64Abs:            "f64.abs",
	opcodeF64Neg:            "f64.neg",
	opcodeF64Copysign:       "f64.copysign",
	opcodeF64Ceil:           "f64.ceil",
	opcodeF64Floor:          "f64.floor",
	opcodeF64Trunc:          "f64.trunc",
	opcodeF64Nearest:        "f64.nearest",
	opcodeF64Sqrt:           "f64.sqrt",
	opcodeF64Eq:             "f64.eq",
	opcodeF64Ne:             "f64.ne",
	opcodeF64Lt:             "f64.lt",
	opcodeF64Le:             "f64.le",
	opcodeF64Gt:             "f64.gt",
	opcodeF64Ge:             "f64.ge",
	opcodeI32TruncSF32:      "i32.trunc_s/f32",
	opcodeI32TruncSF64:      "i32.trunc_s/f64",
	opcodeI32TruncUF32:      "i32.trunc_u/f32",
	opcodeI32TruncUF64:      "i32.trunc_u/f64",
	opcodeI32WrapI64:        "i32.wrap/i64",
	opcodeI64TruncSF32:      "i64.trunc_s/f32",
	opcodeI64TruncSF64:      "i64.trunc_s/f64",
	opcodeI64TruncUF32:      "i64.trunc_u/f32",
	opcodeI64TruncUF64:      "i64.trunc_u/f64",
	opcodeI64ExtendSI32:     "i64.extend_s/i32",
	opcodeI64ExtendUI32:     "i64.extend_u/i32",
	opcodeF32ConvertSI32:    "f32.convert_s/i32",
	opcodeF32ConvertUI32:    "f32.convert_u/i32",
	opcodeF32ConvertSI64:    "f32.convert_s/i64",
	opcodeF32ConvertUI64:    "f32.convert_u/i64",
	opcodeF32DemoteF64:      "f32.demote/f64",
	opcodeF32ReinterpretI32: "f32.reinterpret/i32",
	opcodeF64ConvertSI32:    "f64.convert_s/i32",
	opcodeF64ConvertUI32:    "f64.convert_u/i32",
	opcodeF64ConvertSI64:    "f64.convert_s/i64",
	opcodeF64ConvertUI64:    "f64.convert_u/i64",
	opcodeF64PromoteF32:     "f64.promote/f32",
	opcodeF64ReinterpretI64: "f64.reinterpret/i64",
	opcodeI32ReinterpretF32: "i32.reinterpret/f32",
	opcodeI64ReinterpretF64: "i64.reinterpret/f64",
	opcodeI32Rotr:           "i32.rotr",
	opcodeI32Rotl:           "i32.rotl",
	opcodeI64Rotr:           "i64.rotr",
	opcodeI64Rotl:           "i64.rotl",
	opcodeI64Eqz:            "i64.eqz",
	opcodeGetGlobal:         "get_global",
	opcodeSetGlobal:         "set_global",
}

var opcodeImpls = [256]opImpl{
	opcodeUnreachable:       {genUnreachable, 0},
	opcodeBlock:             {nil, 0}, // initialized by init()
	opcodeLoop:              {nil, 0}, // initialized by init()
	opcodeIf:                {nil, 0}, // initialized by init()
	opcodeElse:              {badGen, 0},
	opcodeSelect:            {genSelect, 0},
	opcodeBr:                {genBr, 0},
	opcodeBrIf:              {genBrIf, 0},
	opcodeBrTable:           {genBrTable, 0},
	opcodeReturn:            {genReturn, 0},
	opcodeNop:               {genNop, 0},
	opcodeDrop:              {genDrop, 0},
	0x0c:                    {badGen, 0},
	0x0d:                    {badGen, 0},
	0x0e:                    {badGen, 0},
	opcodeEnd:               {nil, 0},
	opcodeI32Const:          {genConstI32, opInfo(types.I32)},
	opcodeI64Const:          {genConstI64, opInfo(types.I64)},
	opcodeF64Const:          {genConstF64, opInfo(types.F64)},
	opcodeF32Const:          {genConstF32, opInfo(types.F32)},
	opcodeGetLocal:          {genGetLocal, 0},
	opcodeSetLocal:          {genSetLocal, 0},
	opcodeCall:              {genCall, 0},
	opcodeCallIndirect:      {genCallIndirect, 0},
	0x18:                    {badGen, 0},
	opcodeTeeLocal:          {genTeeLocal, 0},
	0x1a:                    {badGen, 0},
	0x1b:                    {badGen, 0},
	0x1c:                    {badGen, 0},
	0x1d:                    {badGen, 0},
	0x1e:                    {badGen, 0},
	0x1f:                    {badGen, 0},
	opcodeI32Load8S:         {genLoadOp, opInfo(types.I32) | (opInfo(opers.IntLoad8S) << 16)},
	opcodeI32Load8U:         {genLoadOp, opInfo(types.I32) | (opInfo(opers.IntLoad8U) << 16)},
	opcodeI32Load16S:        {genLoadOp, opInfo(types.I32) | (opInfo(opers.IntLoad16S) << 16)},
	opcodeI32Load16U:        {genLoadOp, opInfo(types.I32) | (opInfo(opers.IntLoad16U) << 16)},
	opcodeI64Load8S:         {genLoadOp, opInfo(types.I64) | (opInfo(opers.IntLoad8S) << 16)},
	opcodeI64Load8U:         {genLoadOp, opInfo(types.I64) | (opInfo(opers.IntLoad8U) << 16)},
	opcodeI64Load16S:        {genLoadOp, opInfo(types.I64) | (opInfo(opers.IntLoad16S) << 16)},
	opcodeI64Load16U:        {genLoadOp, opInfo(types.I64) | (opInfo(opers.IntLoad16U) << 16)},
	opcodeI64Load32S:        {genLoadOp, opInfo(types.I64) | (opInfo(opers.IntLoad32S) << 16)},
	opcodeI64Load32U:        {genLoadOp, opInfo(types.I64) | (opInfo(opers.IntLoad32U) << 16)},
	opcodeI32Load:           {genLoadOp, opInfo(types.I32) | (opInfo(opers.I32Load) << 16)},
	opcodeI64Load:           {genLoadOp, opInfo(types.I64) | (opInfo(opers.I64Load) << 16)},
	opcodeF32Load:           {genLoadOp, opInfo(types.F32) | (opInfo(opers.F32Load) << 16)},
	opcodeF64Load:           {genLoadOp, opInfo(types.F64) | (opInfo(opers.F64Load) << 16)},
	opcodeI32Store8:         {genStoreOp, opInfo(types.I32) | (opInfo(opers.IntStore8) << 16)},
	opcodeI32Store16:        {genStoreOp, opInfo(types.I32) | (opInfo(opers.IntStore16) << 16)},
	opcodeI64Store8:         {genStoreOp, opInfo(types.I64) | (opInfo(opers.IntStore8) << 16)},
	opcodeI64Store16:        {genStoreOp, opInfo(types.I64) | (opInfo(opers.IntStore16) << 16)},
	opcodeI64Store32:        {genStoreOp, opInfo(types.I64) | (opInfo(opers.IntStore32) << 16)},
	opcodeI32Store:          {genStoreOp, opInfo(types.I32) | (opInfo(opers.I32Store) << 16)},
	opcodeI64Store:          {genStoreOp, opInfo(types.I64) | (opInfo(opers.I64Store) << 16)},
	opcodeF32Store:          {genStoreOp, opInfo(types.F32) | (opInfo(opers.F32Store) << 16)},
	opcodeF64Store:          {genStoreOp, opInfo(types.F64) | (opInfo(opers.F64Store) << 16)},
	0x37:                    {badGen, 0},
	0x38:                    {badGen, 0},
	opcodeGrowMemory:        {genGrowMemory, 0},
	0x3a:                    {badGen, 0},
	opcodeCurrentMemory:     {genCurrentMemory, 0},
	0x3c:                    {badGen, 0},
	0x3d:                    {badGen, 0},
	0x3e:                    {badGen, 0},
	0x3f:                    {badGen, 0},
	opcodeI32Add:            {genBinaryCommuteOp, opInfo(types.I32) | (opInfo(opers.IntAdd) << 16)},
	opcodeI32Sub:            {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntSub) << 16)},
	opcodeI32Mul:            {genBinaryCommuteOp, opInfo(types.I32) | (opInfo(opers.IntMul) << 16)},
	opcodeI32DivS:           {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntDivS) << 16)},
	opcodeI32DivU:           {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntDivU) << 16)},
	opcodeI32RemS:           {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntRemS) << 16)},
	opcodeI32RemU:           {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntRemU) << 16)},
	opcodeI32And:            {genBinaryCommuteOp, opInfo(types.I32) | (opInfo(opers.IntAnd) << 16)},
	opcodeI32Or:             {genBinaryCommuteOp, opInfo(types.I32) | (opInfo(opers.IntOr) << 16)},
	opcodeI32Xor:            {genBinaryCommuteOp, opInfo(types.I32) | (opInfo(opers.IntXor) << 16)},
	opcodeI32Shl:            {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntShl) << 16)},
	opcodeI32ShrU:           {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntShrU) << 16)},
	opcodeI32ShrS:           {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntShrS) << 16)},
	opcodeI32Eq:             {genBinaryConditionCommuteOp, opInfo(types.I32) | (opInfo(opers.IntEq) << 16)},
	opcodeI32Ne:             {genBinaryConditionCommuteOp, opInfo(types.I32) | (opInfo(opers.IntNe) << 16)},
	opcodeI32LtS:            {genBinaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntLtS) << 16)},
	opcodeI32LeS:            {genBinaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntLeS) << 16)},
	opcodeI32LtU:            {genBinaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntLtU) << 16)},
	opcodeI32LeU:            {genBinaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntLeU) << 16)},
	opcodeI32GtS:            {genBinaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntGtS) << 16)},
	opcodeI32GeS:            {genBinaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntGeS) << 16)},
	opcodeI32GtU:            {genBinaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntGtU) << 16)},
	opcodeI32GeU:            {genBinaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntGeU) << 16)},
	opcodeI32Clz:            {genUnaryOp, opInfo(types.I32) | (opInfo(opers.IntClz) << 16)},
	opcodeI32Ctz:            {genUnaryOp, opInfo(types.I32) | (opInfo(opers.IntCtz) << 16)},
	opcodeI32Popcnt:         {genUnaryOp, opInfo(types.I32) | (opInfo(opers.IntPopcnt) << 16)},
	opcodeI32Eqz:            {genUnaryConditionOp, opInfo(types.I32) | (opInfo(opers.IntEqz) << 16)},
	opcodeI64Add:            {genBinaryCommuteOp, opInfo(types.I64) | (opInfo(opers.IntAdd) << 16)},
	opcodeI64Sub:            {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntSub) << 16)},
	opcodeI64Mul:            {genBinaryCommuteOp, opInfo(types.I64) | (opInfo(opers.IntMul) << 16)},
	opcodeI64DivS:           {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntDivS) << 16)},
	opcodeI64DivU:           {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntDivU) << 16)},
	opcodeI64RemS:           {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntRemS) << 16)},
	opcodeI64RemU:           {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntRemU) << 16)},
	opcodeI64And:            {genBinaryCommuteOp, opInfo(types.I64) | (opInfo(opers.IntAnd) << 16)},
	opcodeI64Or:             {genBinaryCommuteOp, opInfo(types.I64) | (opInfo(opers.IntOr) << 16)},
	opcodeI64Xor:            {genBinaryCommuteOp, opInfo(types.I64) | (opInfo(opers.IntXor) << 16)},
	opcodeI64Shl:            {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntShl) << 16)},
	opcodeI64ShrU:           {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntShrU) << 16)},
	opcodeI64ShrS:           {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntShrS) << 16)},
	opcodeI64Eq:             {genBinaryConditionCommuteOp, opInfo(types.I64) | (opInfo(opers.IntEq) << 16)},
	opcodeI64Ne:             {genBinaryConditionCommuteOp, opInfo(types.I64) | (opInfo(opers.IntNe) << 16)},
	opcodeI64LtS:            {genBinaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntLtS) << 16)},
	opcodeI64LeS:            {genBinaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntLeS) << 16)},
	opcodeI64LtU:            {genBinaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntLtU) << 16)},
	opcodeI64LeU:            {genBinaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntLeU) << 16)},
	opcodeI64GtS:            {genBinaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntGtS) << 16)},
	opcodeI64GeS:            {genBinaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntGeS) << 16)},
	opcodeI64GtU:            {genBinaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntGtU) << 16)},
	opcodeI64GeU:            {genBinaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntGeU) << 16)},
	opcodeI64Clz:            {genUnaryOp, opInfo(types.I64) | (opInfo(opers.IntClz) << 16)},
	opcodeI64Ctz:            {genUnaryOp, opInfo(types.I64) | (opInfo(opers.IntCtz) << 16)},
	opcodeI64Popcnt:         {genUnaryOp, opInfo(types.I64) | (opInfo(opers.IntPopcnt) << 16)},
	opcodeF32Add:            {genBinaryCommuteOp, opInfo(types.F32) | (opInfo(opers.FloatAdd) << 16)},
	opcodeF32Sub:            {genBinaryOp, opInfo(types.F32) | (opInfo(opers.FloatSub) << 16)},
	opcodeF32Mul:            {genBinaryCommuteOp, opInfo(types.F32) | (opInfo(opers.FloatMul) << 16)},
	opcodeF32Div:            {genBinaryOp, opInfo(types.F32) | (opInfo(opers.FloatDiv) << 16)},
	opcodeF32Min:            {genBinaryCommuteOp, opInfo(types.F32) | (opInfo(opers.FloatMin) << 16)},
	opcodeF32Max:            {genBinaryCommuteOp, opInfo(types.F32) | (opInfo(opers.FloatMax) << 16)},
	opcodeF32Abs:            {genUnaryOp, opInfo(types.F32) | (opInfo(opers.FloatAbs) << 16)},
	opcodeF32Neg:            {genUnaryOp, opInfo(types.F32) | (opInfo(opers.FloatNeg) << 16)},
	opcodeF32Copysign:       {genUnaryOp, opInfo(types.F32) | (opInfo(opers.FloatCopysign) << 16)},
	opcodeF32Ceil:           {genUnaryOp, opInfo(types.F32) | (opInfo(opers.FloatCeil) << 16)},
	opcodeF32Floor:          {genUnaryOp, opInfo(types.F32) | (opInfo(opers.FloatFloor) << 16)},
	opcodeF32Trunc:          {genUnaryOp, opInfo(types.F32) | (opInfo(opers.FloatTrunc) << 16)},
	opcodeF32Nearest:        {genUnaryOp, opInfo(types.F32) | (opInfo(opers.FloatNearest) << 16)},
	opcodeF32Sqrt:           {genUnaryOp, opInfo(types.F32) | (opInfo(opers.FloatSqrt) << 16)},
	opcodeF32Eq:             {genBinaryConditionCommuteOp, opInfo(types.F32) | (opInfo(opers.FloatEq) << 16)},
	opcodeF32Ne:             {genBinaryConditionCommuteOp, opInfo(types.F32) | (opInfo(opers.FloatNe) << 16)},
	opcodeF32Lt:             {genBinaryConditionOp, opInfo(types.F32) | (opInfo(opers.FloatLt) << 16)},
	opcodeF32Le:             {genBinaryConditionOp, opInfo(types.F32) | (opInfo(opers.FloatLe) << 16)},
	opcodeF32Gt:             {genBinaryConditionOp, opInfo(types.F32) | (opInfo(opers.FloatGt) << 16)},
	opcodeF32Ge:             {genBinaryConditionOp, opInfo(types.F32) | (opInfo(opers.FloatGe) << 16)},
	opcodeF64Add:            {genBinaryCommuteOp, opInfo(types.F64) | (opInfo(opers.FloatAdd) << 16)},
	opcodeF64Sub:            {genBinaryOp, opInfo(types.F64) | (opInfo(opers.FloatSub) << 16)},
	opcodeF64Mul:            {genBinaryCommuteOp, opInfo(types.F64) | (opInfo(opers.FloatMul) << 16)},
	opcodeF64Div:            {genBinaryOp, opInfo(types.F64) | (opInfo(opers.FloatDiv) << 16)},
	opcodeF64Min:            {genBinaryCommuteOp, opInfo(types.F64) | (opInfo(opers.FloatMin) << 16)},
	opcodeF64Max:            {genBinaryCommuteOp, opInfo(types.F64) | (opInfo(opers.FloatMax) << 16)},
	opcodeF64Abs:            {genUnaryOp, opInfo(types.F64) | (opInfo(opers.FloatAbs) << 16)},
	opcodeF64Neg:            {genUnaryOp, opInfo(types.F64) | (opInfo(opers.FloatNeg) << 16)},
	opcodeF64Copysign:       {genUnaryOp, opInfo(types.F64) | (opInfo(opers.FloatCopysign) << 16)},
	opcodeF64Ceil:           {genUnaryOp, opInfo(types.F64) | (opInfo(opers.FloatCeil) << 16)},
	opcodeF64Floor:          {genUnaryOp, opInfo(types.F64) | (opInfo(opers.FloatFloor) << 16)},
	opcodeF64Trunc:          {genUnaryOp, opInfo(types.F64) | (opInfo(opers.FloatTrunc) << 16)},
	opcodeF64Nearest:        {genUnaryOp, opInfo(types.F64) | (opInfo(opers.FloatNearest) << 16)},
	opcodeF64Sqrt:           {genUnaryOp, opInfo(types.F64) | (opInfo(opers.FloatSqrt) << 16)},
	opcodeF64Eq:             {genBinaryConditionCommuteOp, opInfo(types.F64) | (opInfo(opers.FloatEq) << 16)},
	opcodeF64Ne:             {genBinaryConditionCommuteOp, opInfo(types.F64) | (opInfo(opers.FloatNe) << 16)},
	opcodeF64Lt:             {genBinaryConditionOp, opInfo(types.F64) | (opInfo(opers.FloatLt) << 16)},
	opcodeF64Le:             {genBinaryConditionOp, opInfo(types.F64) | (opInfo(opers.FloatLe) << 16)},
	opcodeF64Gt:             {genBinaryConditionOp, opInfo(types.F64) | (opInfo(opers.FloatGt) << 16)},
	opcodeF64Ge:             {genBinaryConditionOp, opInfo(types.F64) | (opInfo(opers.FloatGe) << 16)},
	opcodeI32TruncSF32:      {genConversionOp, opInfo(types.I32) | (opInfo(types.F32) << 8) | (opInfo(opers.TruncS) << 16)},
	opcodeI32TruncSF64:      {genConversionOp, opInfo(types.I32) | (opInfo(types.F64) << 8) | (opInfo(opers.TruncS) << 16)},
	opcodeI32TruncUF32:      {genConversionOp, opInfo(types.I32) | (opInfo(types.F32) << 8) | (opInfo(opers.TruncU) << 16)},
	opcodeI32TruncUF64:      {genConversionOp, opInfo(types.I32) | (opInfo(types.F64) << 8) | (opInfo(opers.TruncU) << 16)},
	opcodeI32WrapI64:        {genConversionOp, opInfo(types.I32) | (opInfo(types.I64) << 8) | (opInfo(opers.Wrap) << 16)},
	opcodeI64TruncSF32:      {genConversionOp, opInfo(types.I64) | (opInfo(types.F32) << 8) | (opInfo(opers.TruncS) << 16)},
	opcodeI64TruncSF64:      {genConversionOp, opInfo(types.I64) | (opInfo(types.F64) << 8) | (opInfo(opers.TruncS) << 16)},
	opcodeI64TruncUF32:      {genConversionOp, opInfo(types.I64) | (opInfo(types.F32) << 8) | (opInfo(opers.TruncU) << 16)},
	opcodeI64TruncUF64:      {genConversionOp, opInfo(types.I64) | (opInfo(types.F64) << 8) | (opInfo(opers.TruncU) << 16)},
	opcodeI64ExtendSI32:     {genConversionOp, opInfo(types.I64) | (opInfo(types.I32) << 8) | (opInfo(opers.ExtendS) << 16)},
	opcodeI64ExtendUI32:     {genConversionOp, opInfo(types.I64) | (opInfo(types.I32) << 8) | (opInfo(opers.ExtendU) << 16)},
	opcodeF32ConvertSI32:    {genConversionOp, opInfo(types.F32) | (opInfo(types.I32) << 8) | (opInfo(opers.ConvertS) << 16)},
	opcodeF32ConvertUI32:    {genConversionOp, opInfo(types.F32) | (opInfo(types.I32) << 8) | (opInfo(opers.ConvertU) << 16)},
	opcodeF32ConvertSI64:    {genConversionOp, opInfo(types.F32) | (opInfo(types.I64) << 8) | (opInfo(opers.ConvertS) << 16)},
	opcodeF32ConvertUI64:    {genConversionOp, opInfo(types.F32) | (opInfo(types.I64) << 8) | (opInfo(opers.ConvertU) << 16)},
	opcodeF32DemoteF64:      {genConversionOp, opInfo(types.F32) | (opInfo(types.F64) << 8) | (opInfo(opers.Demote) << 16)},
	opcodeF32ReinterpretI32: {genConversionOp, opInfo(types.F32) | (opInfo(types.I32) << 8) | (opInfo(opers.Reinterpret) << 16)},
	opcodeF64ConvertSI32:    {genConversionOp, opInfo(types.F64) | (opInfo(types.I32) << 8) | (opInfo(opers.ConvertS) << 16)},
	opcodeF64ConvertUI32:    {genConversionOp, opInfo(types.F64) | (opInfo(types.I32) << 8) | (opInfo(opers.ConvertU) << 16)},
	opcodeF64ConvertSI64:    {genConversionOp, opInfo(types.F64) | (opInfo(types.I64) << 8) | (opInfo(opers.ConvertS) << 16)},
	opcodeF64ConvertUI64:    {genConversionOp, opInfo(types.F64) | (opInfo(types.I64) << 8) | (opInfo(opers.ConvertU) << 16)},
	opcodeF64PromoteF32:     {genConversionOp, opInfo(types.F64) | (opInfo(types.F32) << 8) | (opInfo(opers.Promote) << 16)},
	opcodeF64ReinterpretI64: {genConversionOp, opInfo(types.F64) | (opInfo(types.I64) << 8) | (opInfo(opers.Reinterpret) << 16)},
	opcodeI32ReinterpretF32: {genConversionOp, opInfo(types.I32) | (opInfo(types.F32) << 8) | (opInfo(opers.Reinterpret) << 16)},
	opcodeI64ReinterpretF64: {genConversionOp, opInfo(types.I64) | (opInfo(types.F64) << 8) | (opInfo(opers.Reinterpret) << 16)},
	opcodeI32Rotr:           {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntRotr) << 16)},
	opcodeI32Rotl:           {genBinaryOp, opInfo(types.I32) | (opInfo(opers.IntRotl) << 16)},
	opcodeI64Rotr:           {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntRotr) << 16)},
	opcodeI64Rotl:           {genBinaryOp, opInfo(types.I64) | (opInfo(opers.IntRotl) << 16)},
	opcodeI64Eqz:            {genUnaryConditionOp, opInfo(types.I64) | (opInfo(opers.IntEqz) << 16)},
	opcodeGetGlobal:         {genGetGlobal, 0},
	opcodeSetGlobal:         {genSetGlobal, 0},
	0xbd:                    {badGen, 0},
	0xbe:                    {badGen, 0},
	0xbf:                    {badGen, 0},
	0xc0:                    {badGen, 0},
	0xc1:                    {badGen, 0},
	0xc2:                    {badGen, 0},
	0xc3:                    {badGen, 0},
	0xc4:                    {badGen, 0},
	0xc5:                    {badGen, 0},
	0xc6:                    {badGen, 0},
	0xc7:                    {badGen, 0},
	0xc8:                    {badGen, 0},
	0xc9:                    {badGen, 0},
	0xca:                    {badGen, 0},
	0xcb:                    {badGen, 0},
	0xcc:                    {badGen, 0},
	0xcd:                    {badGen, 0},
	0xce:                    {badGen, 0},
	0xcf:                    {badGen, 0},
	0xd0:                    {badGen, 0},
	0xd1:                    {badGen, 0},
	0xd2:                    {badGen, 0},
	0xd3:                    {badGen, 0},
	0xd4:                    {badGen, 0},
	0xd5:                    {badGen, 0},
	0xd6:                    {badGen, 0},
	0xd7:                    {badGen, 0},
	0xd8:                    {badGen, 0},
	0xd9:                    {badGen, 0},
	0xda:                    {badGen, 0},
	0xdb:                    {badGen, 0},
	0xdc:                    {badGen, 0},
	0xdd:                    {badGen, 0},
	0xde:                    {badGen, 0},
	0xdf:                    {badGen, 0},
	0xe0:                    {badGen, 0},
	0xe1:                    {badGen, 0},
	0xe2:                    {badGen, 0},
	0xe3:                    {badGen, 0},
	0xe4:                    {badGen, 0},
	0xe5:                    {badGen, 0},
	0xe6:                    {badGen, 0},
	0xe7:                    {badGen, 0},
	0xe8:                    {badGen, 0},
	0xe9:                    {badGen, 0},
	0xea:                    {badGen, 0},
	0xeb:                    {badGen, 0},
	0xec:                    {badGen, 0},
	0xed:                    {badGen, 0},
	0xee:                    {badGen, 0},
	0xef:                    {badGen, 0},
	0xf0:                    {badGen, 0},
	0xf1:                    {badGen, 0},
	0xf2:                    {badGen, 0},
	0xf3:                    {badGen, 0},
	0xf4:                    {badGen, 0},
	0xf5:                    {badGen, 0},
	0xf6:                    {badGen, 0},
	0xf7:                    {badGen, 0},
	0xf8:                    {badGen, 0},
	0xf9:                    {badGen, 0},
	0xfa:                    {badGen, 0},
	0xfb:                    {badGen, 0},
	0xfc:                    {badGen, 0},
	0xfd:                    {badGen, 0},
	0xfe:                    {badGen, 0},
	0xff:                    {badGen, 0},
}

var opcodeSkips = [256]func(reader, opcode){
	opcodeUnreachable:       skipNothing,
	opcodeBlock:             nil, // initialized by init()
	opcodeLoop:              nil, // initialized by init()
	opcodeIf:                nil, // initialized by init()
	opcodeElse:              badSkip,
	opcodeSelect:            skipNothing,
	opcodeBr:                skipVaruint32,
	opcodeBrIf:              skipVaruint32,
	opcodeBrTable:           skipBrTable,
	opcodeReturn:            skipNothing,
	opcodeNop:               skipNothing,
	opcodeDrop:              skipNothing,
	0x0c:                    badSkip,
	0x0d:                    badSkip,
	0x0e:                    badSkip,
	opcodeEnd:               nil,
	opcodeI32Const:          skipVarint32,
	opcodeI64Const:          skipVarint64,
	opcodeF64Const:          skipUint64,
	opcodeF32Const:          skipUint32,
	opcodeGetLocal:          skipVaruint32,
	opcodeSetLocal:          skipVaruint32,
	opcodeCall:              skipVaruint32,
	opcodeCallIndirect:      skipVaruint32,
	0x18:                    badSkip,
	opcodeTeeLocal:          skipVaruint32,
	0x1a:                    badSkip,
	0x1b:                    badSkip,
	0x1c:                    badSkip,
	0x1d:                    badSkip,
	0x1e:                    badSkip,
	0x1f:                    badSkip,
	opcodeI32Load8S:         skipMemoryImmediate,
	opcodeI32Load8U:         skipMemoryImmediate,
	opcodeI32Load16S:        skipMemoryImmediate,
	opcodeI32Load16U:        skipMemoryImmediate,
	opcodeI64Load8S:         skipMemoryImmediate,
	opcodeI64Load8U:         skipMemoryImmediate,
	opcodeI64Load16S:        skipMemoryImmediate,
	opcodeI64Load16U:        skipMemoryImmediate,
	opcodeI64Load32S:        skipMemoryImmediate,
	opcodeI64Load32U:        skipMemoryImmediate,
	opcodeI32Load:           skipMemoryImmediate,
	opcodeI64Load:           skipMemoryImmediate,
	opcodeF32Load:           skipMemoryImmediate,
	opcodeF64Load:           skipMemoryImmediate,
	opcodeI32Store8:         skipMemoryImmediate,
	opcodeI32Store16:        skipMemoryImmediate,
	opcodeI64Store8:         skipMemoryImmediate,
	opcodeI64Store16:        skipMemoryImmediate,
	opcodeI64Store32:        skipMemoryImmediate,
	opcodeI32Store:          skipMemoryImmediate,
	opcodeI64Store:          skipMemoryImmediate,
	opcodeF32Store:          skipMemoryImmediate,
	opcodeF64Store:          skipMemoryImmediate,
	0x37:                    badSkip,
	0x38:                    badSkip,
	opcodeGrowMemory:        skipNothing,
	0x3a:                    badSkip,
	opcodeCurrentMemory:     skipNothing,
	0x3c:                    badSkip,
	0x3d:                    badSkip,
	0x3e:                    badSkip,
	0x3f:                    badSkip,
	opcodeI32Add:            skipNothing,
	opcodeI32Sub:            skipNothing,
	opcodeI32Mul:            skipNothing,
	opcodeI32DivS:           skipNothing,
	opcodeI32DivU:           skipNothing,
	opcodeI32RemS:           skipNothing,
	opcodeI32RemU:           skipNothing,
	opcodeI32And:            skipNothing,
	opcodeI32Or:             skipNothing,
	opcodeI32Xor:            skipNothing,
	opcodeI32Shl:            skipNothing,
	opcodeI32ShrU:           skipNothing,
	opcodeI32ShrS:           skipNothing,
	opcodeI32Eq:             skipNothing,
	opcodeI32Ne:             skipNothing,
	opcodeI32LtS:            skipNothing,
	opcodeI32LeS:            skipNothing,
	opcodeI32LtU:            skipNothing,
	opcodeI32LeU:            skipNothing,
	opcodeI32GtS:            skipNothing,
	opcodeI32GeS:            skipNothing,
	opcodeI32GtU:            skipNothing,
	opcodeI32GeU:            skipNothing,
	opcodeI32Clz:            skipNothing,
	opcodeI32Ctz:            skipNothing,
	opcodeI32Popcnt:         skipNothing,
	opcodeI32Eqz:            skipNothing,
	opcodeI64Add:            skipNothing,
	opcodeI64Sub:            skipNothing,
	opcodeI64Mul:            skipNothing,
	opcodeI64DivS:           skipNothing,
	opcodeI64DivU:           skipNothing,
	opcodeI64RemS:           skipNothing,
	opcodeI64RemU:           skipNothing,
	opcodeI64And:            skipNothing,
	opcodeI64Or:             skipNothing,
	opcodeI64Xor:            skipNothing,
	opcodeI64Shl:            skipNothing,
	opcodeI64ShrU:           skipNothing,
	opcodeI64ShrS:           skipNothing,
	opcodeI64Eq:             skipNothing,
	opcodeI64Ne:             skipNothing,
	opcodeI64LtS:            skipNothing,
	opcodeI64LeS:            skipNothing,
	opcodeI64LtU:            skipNothing,
	opcodeI64LeU:            skipNothing,
	opcodeI64GtS:            skipNothing,
	opcodeI64GeS:            skipNothing,
	opcodeI64GtU:            skipNothing,
	opcodeI64GeU:            skipNothing,
	opcodeI64Clz:            skipNothing,
	opcodeI64Ctz:            skipNothing,
	opcodeI64Popcnt:         skipNothing,
	opcodeF32Add:            skipNothing,
	opcodeF32Sub:            skipNothing,
	opcodeF32Mul:            skipNothing,
	opcodeF32Div:            skipNothing,
	opcodeF32Min:            skipNothing,
	opcodeF32Max:            skipNothing,
	opcodeF32Abs:            skipNothing,
	opcodeF32Neg:            skipNothing,
	opcodeF32Copysign:       skipNothing,
	opcodeF32Ceil:           skipNothing,
	opcodeF32Floor:          skipNothing,
	opcodeF32Trunc:          skipNothing,
	opcodeF32Nearest:        skipNothing,
	opcodeF32Sqrt:           skipNothing,
	opcodeF32Eq:             skipNothing,
	opcodeF32Ne:             skipNothing,
	opcodeF32Lt:             skipNothing,
	opcodeF32Le:             skipNothing,
	opcodeF32Gt:             skipNothing,
	opcodeF32Ge:             skipNothing,
	opcodeF64Add:            skipNothing,
	opcodeF64Sub:            skipNothing,
	opcodeF64Mul:            skipNothing,
	opcodeF64Div:            skipNothing,
	opcodeF64Min:            skipNothing,
	opcodeF64Max:            skipNothing,
	opcodeF64Abs:            skipNothing,
	opcodeF64Neg:            skipNothing,
	opcodeF64Copysign:       skipNothing,
	opcodeF64Ceil:           skipNothing,
	opcodeF64Floor:          skipNothing,
	opcodeF64Trunc:          skipNothing,
	opcodeF64Nearest:        skipNothing,
	opcodeF64Sqrt:           skipNothing,
	opcodeF64Eq:             skipNothing,
	opcodeF64Ne:             skipNothing,
	opcodeF64Lt:             skipNothing,
	opcodeF64Le:             skipNothing,
	opcodeF64Gt:             skipNothing,
	opcodeF64Ge:             skipNothing,
	opcodeI32TruncSF32:      skipNothing,
	opcodeI32TruncSF64:      skipNothing,
	opcodeI32TruncUF32:      skipNothing,
	opcodeI32TruncUF64:      skipNothing,
	opcodeI32WrapI64:        skipNothing,
	opcodeI64TruncSF32:      skipNothing,
	opcodeI64TruncSF64:      skipNothing,
	opcodeI64TruncUF32:      skipNothing,
	opcodeI64TruncUF64:      skipNothing,
	opcodeI64ExtendSI32:     skipNothing,
	opcodeI64ExtendUI32:     skipNothing,
	opcodeF32ConvertSI32:    skipNothing,
	opcodeF32ConvertUI32:    skipNothing,
	opcodeF32ConvertSI64:    skipNothing,
	opcodeF32ConvertUI64:    skipNothing,
	opcodeF32DemoteF64:      skipNothing,
	opcodeF32ReinterpretI32: skipNothing,
	opcodeF64ConvertSI32:    skipNothing,
	opcodeF64ConvertUI32:    skipNothing,
	opcodeF64ConvertSI64:    skipNothing,
	opcodeF64ConvertUI64:    skipNothing,
	opcodeF64PromoteF32:     skipNothing,
	opcodeF64ReinterpretI64: skipNothing,
	opcodeI32ReinterpretF32: skipNothing,
	opcodeI64ReinterpretF64: skipNothing,
	opcodeI32Rotr:           skipNothing,
	opcodeI32Rotl:           skipNothing,
	opcodeI64Rotr:           skipNothing,
	opcodeI64Rotl:           skipNothing,
	opcodeI64Eqz:            skipNothing,
	opcodeGetGlobal:         skipVaruint32,
	opcodeSetGlobal:         skipVaruint32,
	0xbd:                    badSkip,
	0xbe:                    badSkip,
	0xbf:                    badSkip,
	0xc0:                    badSkip,
	0xc1:                    badSkip,
	0xc2:                    badSkip,
	0xc3:                    badSkip,
	0xc4:                    badSkip,
	0xc5:                    badSkip,
	0xc6:                    badSkip,
	0xc7:                    badSkip,
	0xc8:                    badSkip,
	0xc9:                    badSkip,
	0xca:                    badSkip,
	0xcb:                    badSkip,
	0xcc:                    badSkip,
	0xcd:                    badSkip,
	0xce:                    badSkip,
	0xcf:                    badSkip,
	0xd0:                    badSkip,
	0xd1:                    badSkip,
	0xd2:                    badSkip,
	0xd3:                    badSkip,
	0xd4:                    badSkip,
	0xd5:                    badSkip,
	0xd6:                    badSkip,
	0xd7:                    badSkip,
	0xd8:                    badSkip,
	0xd9:                    badSkip,
	0xda:                    badSkip,
	0xdb:                    badSkip,
	0xdc:                    badSkip,
	0xdd:                    badSkip,
	0xde:                    badSkip,
	0xdf:                    badSkip,
	0xe0:                    badSkip,
	0xe1:                    badSkip,
	0xe2:                    badSkip,
	0xe3:                    badSkip,
	0xe4:                    badSkip,
	0xe5:                    badSkip,
	0xe6:                    badSkip,
	0xe7:                    badSkip,
	0xe8:                    badSkip,
	0xe9:                    badSkip,
	0xea:                    badSkip,
	0xeb:                    badSkip,
	0xec:                    badSkip,
	0xed:                    badSkip,
	0xee:                    badSkip,
	0xef:                    badSkip,
	0xf0:                    badSkip,
	0xf1:                    badSkip,
	0xf2:                    badSkip,
	0xf3:                    badSkip,
	0xf4:                    badSkip,
	0xf5:                    badSkip,
	0xf6:                    badSkip,
	0xf7:                    badSkip,
	0xf8:                    badSkip,
	0xf9:                    badSkip,
	0xfa:                    badSkip,
	0xfb:                    badSkip,
	0xfc:                    badSkip,
	0xfd:                    badSkip,
	0xfe:                    badSkip,
	0xff:                    badSkip,
}
