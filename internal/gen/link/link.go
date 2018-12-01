// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package link

import (
	"github.com/pkg/errors"
)

type L struct {
	Sites []int32
	Addr  int32
}

func (l *L) AddSite(addr int32) {
	l.Sites = append(l.Sites, addr)
}

func (l *L) AddSites(addrs []int32) {
	l.Sites = append(l.Sites, addrs...)
}

func (l *L) FinalAddr() int32 {
	if l.Addr == 0 {
		panic(errors.New("link address undefined while updating branch or call instruction"))
	}
	return l.Addr
}

type FuncL struct {
	L
	TableIndexes []int
}

func (fl *FuncL) AddTableIndex(index int) {
	fl.TableIndexes = append(fl.TableIndexes, index)
}
