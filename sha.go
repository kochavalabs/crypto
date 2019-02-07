package crypto

import (
	"golang.org/x/crypto/sha3"
)

// Sha3_256 is a SHA-3-256 hasher. Its generic security strength is
// 256 bits against preimage attacks, and 128 bits against collision attacks.
// data is an arbitrary length bytes slice returns 32 bytes ( 256 bits ) hash
// of data.
//
// Implements the crypto.Hasher interface.
type Sha3_256Hasher struct {
}

func (h *Sha3_256Hasher) Hash(input ...[]byte) []byte {
	return hashBytes(sha3.New256(), input...)
}

func (h *Sha3_256Hasher) HashHex(input ...[]byte) string {
	return hashHex(sha3.New256(), input...)
}
