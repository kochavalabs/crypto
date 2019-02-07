package crypto

import (
	"golang.org/x/crypto/sha3"
)

// Keccak256 is a cryptographic hashing algorithm  Its generic security strength
// is 256 bits against preimage attacks, and 128 bits against collision attacks.
// A slightly modified version of keccak was adopted for the SHA3 standard. This
// is the legacy version of the hash.
//
// Implements the crypto.Hasher interface.
type Keccak256Hasher struct {
}

func (h *Keccak256Hasher) Hash(input ...[]byte) []byte {
	return hashBytes(sha3.NewLegacyKeccak256(), input...)
}

func (h *Keccak256Hasher) HashHex(input ...[]byte) string {
	return hashHex(sha3.NewLegacyKeccak256(), input...)
}
