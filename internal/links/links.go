package links

type L struct {
	Sites   []int
	Address int
}

func (l *L) AddSite(addr int) {
	l.Sites = append(l.Sites, addr)
}
