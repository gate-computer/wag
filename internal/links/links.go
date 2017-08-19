// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package links

type L struct {
	Sites []int32
	Addr  int32
}

func (l *L) Reset() {
	l.Sites = nil
	l.Addr = 0
}

func (l *L) SetLive() {
	if l.Sites == nil {
		l.Sites = []int32{}
	}
}

func (l *L) Live() bool {
	return l.Sites != nil
}

func (l *L) AddSite(addr int32) {
	l.Sites = append(l.Sites, addr)
}

func (l *L) FinalAddr() int32 {
	if l.Addr == 0 {
		panic("link address is undefined")
	}
	return l.Addr
}

type FunctionL struct {
	L
	TableIndexes []int
}

func (fl *FunctionL) AddTableIndex(index int) {
	fl.TableIndexes = append(fl.TableIndexes, index)
}
