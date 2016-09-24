package types

type Function struct {
	Args   []T
	Result T
}

func (f Function) String() (s string) {
	s = "("
	for i, t := range f.Args {
		if i > 0 {
			s += ", "
		}
		s += t.String()
	}
	s += ") " + f.Result.String()
	return
}
