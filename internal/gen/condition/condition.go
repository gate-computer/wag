// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package condition

type C int

const (
	Eq = C(iota)
	Ne
	GeS
	GtS
	GeU
	GtU
	LeS
	LtS
	LeU
	LtU

	OrderedAndEq
	OrderedAndNe
	OrderedAndGe
	OrderedAndGt
	OrderedAndLe
	OrderedAndLt

	UnorderedOrEq
	UnorderedOrNe
	UnorderedOrGe
	UnorderedOrGt
	UnorderedOrLe
	UnorderedOrLt
)

const (
	MinOrderedAndCondition  = OrderedAndEq
	MinUnorderedOrCondition = UnorderedOrEq
)

var Inverted = [22]C{
	Eq:            Ne,
	Ne:            Eq,
	GeS:           LtS,
	GtS:           LeS,
	GeU:           LtU,
	GtU:           LeU,
	LeS:           GtS,
	LtS:           GeS,
	LeU:           GtU,
	LtU:           GeU,
	OrderedAndEq:  UnorderedOrNe,
	OrderedAndNe:  UnorderedOrEq,
	OrderedAndGe:  UnorderedOrLt,
	OrderedAndGt:  UnorderedOrLe,
	OrderedAndLe:  UnorderedOrGt,
	OrderedAndLt:  UnorderedOrGe,
	UnorderedOrEq: OrderedAndNe,
	UnorderedOrNe: OrderedAndEq,
	UnorderedOrGe: OrderedAndLt,
	UnorderedOrGt: OrderedAndLe,
	UnorderedOrLe: OrderedAndGt,
	UnorderedOrLt: OrderedAndGe,
}

var strings = []string{
	Eq:            "equal",
	Ne:            "not-equal",
	GeS:           "signed greater-or-equal",
	GtS:           "signed greater",
	GeU:           "unsigned greater-or-equal",
	GtU:           "unsigned greater",
	LeS:           "signed less-or-equal",
	LtS:           "signed less",
	LeU:           "unsigned less-or-equal",
	LtU:           "unsigned less",
	OrderedAndEq:  "ordered-and-equal",
	OrderedAndNe:  "ordered-and-not-equal",
	OrderedAndGe:  "ordered-and-greater-or-equal",
	OrderedAndGt:  "ordered-and-greater",
	OrderedAndLe:  "ordered-and-less-or-equal",
	OrderedAndLt:  "ordered-and-less",
	UnorderedOrEq: "unordered-or-equal",
	UnorderedOrNe: "unordered-or-not-equal",
	UnorderedOrGe: "unordered-or-greater-or-equal",
	UnorderedOrGt: "unordered-or-greater",
	UnorderedOrLe: "unordered-or-less-or-equal",
	UnorderedOrLt: "unordered-or-less",
}

func (f C) String() string {
	if i := int(f); i < len(strings) {
		return strings[i]
	} else {
		return "<invalid condition>"
	}
}
