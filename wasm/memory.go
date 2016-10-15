package wasm

type MemorySize int

const (
	PageBits            = 16
	Page     MemorySize = 1 << PageBits
)
