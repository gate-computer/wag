// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gen

import "testing"

func checkLocalOffsets(t *testing.T, f *Func, table [][2]int) {
	t.Helper()

	for _, pair := range table {
		if actual := f.LocalOffset(pair[0]); actual != int32(pair[1]) {
			t.Errorf("LocalOffset(%d) should be %d but is actually %d", pair[0], pair[1], actual)
		}
	}
}

func TestLocalOffset(t *testing.T) {
	const (
		numParams = 5
		numOthers = 8
	)

	t.Run("Valid", func(t *testing.T) {
		checkLocalOffsets(t, &Func{
			NumParams:  numParams,
			StackDepth: numOthers,
		}, [][2]int{
			{0, 104}, // params
			{1, 96},
			{2, 88},
			{3, 80},
			{4, 72},
			{5, 56}, // non-params
			{6, 48},
			{7, 40},
			{8, 32},
			{9, 24},
			{10, 16},
			{11, 8},
			{12, 0},
		})
	})

	t.Run("Valid+1", func(t *testing.T) {
		checkLocalOffsets(t, &Func{
			NumParams:  numParams,
			StackDepth: numOthers + 1,
		}, [][2]int{
			{0, 112}, // params
			{1, 104},
			{2, 96},
			{3, 88},
			{4, 80},
			{5, 64}, // non-params
			{6, 56},
			{7, 48},
			{8, 40},
			{9, 32},
			{10, 24},
			{11, 16},
			{12, 8},
		})
	})

	t.Run("IndexOutOfRange", func(t *testing.T) {
		defer func() { recover() }()
		f := Func{
			NumParams:  numParams,
			StackDepth: numOthers,
		}
		f.LocalOffset(numParams + numOthers)
		t.Fail()
	})
}
