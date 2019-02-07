package crypto

import (
	"golang.org/x/crypto/sha3"
)

// Shake is a cryptographic hashing algorithm. It differs from most common
// hashing algorithms in that it is of variable length. Here we are providing
// a version of shake that returns a 256bit message digest.
//
// Implements the crypto.Hasher interface.
type Shake256Hasher struct {
}

func (h *Shake256Hasher) Hash(input ...[]byte) []byte {
	hash := make([]byte, 32)
	hashFunc := sha3.NewShake256()
	for _, b := range input {
		hashFunc.Write(b)
	}
	hashFunc.Read(hash)
	return hash
}

func (h *Shake256Hasher) HashHex(input ...[]byte) string {
	return ToHex(h.Hash(input...))
}
