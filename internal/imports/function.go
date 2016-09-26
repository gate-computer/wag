package imports

import (
	"fmt"

	"github.com/tsavola/wag/internal/types"
)

type Function struct {
	types.Function
	Variadic bool
	Address  int64
}

func (impl Function) Implements(signature types.Function) bool {
	if impl.Variadic {
		return impl.Function.EqualVariadic(signature)
	} else {
		return impl.Function.Equal(signature)
	}
}

func (f Function) String() (s string) {
	s = fmt.Sprintf("0x%x (", f.Address)
	for i, t := range f.Args {
		if i > 0 {
			s += ", "
		}
		s += t.String()
	}
	if f.Variadic {
		s += "..."
	}
	s += ") " + f.Result.String()
	return
}
