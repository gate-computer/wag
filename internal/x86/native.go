// +build amd64

package x86

const Native = true

func atomicPutUint32(b []byte, val uint32)

func (X86) PutUint32(b []byte, val uint32) {
	atomicPutUint32(b, val)
}
