package gen

import (
	"bytes"

	"github.com/tsavola/wag/internal/links"
)

type Coder struct {
	bytes.Buffer

	TrapDivideByZero          links.L
	TrapCallStackExhausted    links.L
	TrapIndirectCallIndex     links.L
	TrapIndirectCallSignature links.L
	TrapUnreachable           links.L
}
