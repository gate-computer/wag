package gen

func RegMask(available ...bool) (mask uint32) {
	for i, a := range available {
		if a {
			mask |= 1 << uint(i)
		}
	}
	return
}
