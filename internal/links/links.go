package links

type L struct {
	Sites   []int
	Address int
}

func (l *L) SetLive() {
	if l.Sites == nil {
		l.Sites = []int{}
	}
}

func (l *L) Live() bool {
	return l.Sites != nil
}

func (l *L) AddSite(addr int) {
	l.Sites = append(l.Sites, addr)
}

func (l *L) SetAddress(addr int) {
	if l.Address != 0 {
		panic("link address defined twice")
	}
	l.Address = addr
}

func (l *L) FinalAddress() int {
	if l.Address <= 0 {
		panic("link address is undefined")
	}
	return l.Address
}
