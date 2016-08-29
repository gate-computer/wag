package stubs

type Function struct {
	Name      string
	CallSites []int
	Address   int
}

type Label struct {
	BranchSites []int
	Address     int
}
