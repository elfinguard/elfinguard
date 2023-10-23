//go:build arm64
// +build arm64

package types

import (
	"crypto/rand"
)

// implements io.Reader
func (r *RandReader) Read(out []byte) (n int, err error) {
	return rand.Read(out)
}
