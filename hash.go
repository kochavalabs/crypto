package crypto

import (
	"hash"
)

type Hasher interface {
	Hash(input ...[]byte) []byte
	HashHex(input ...[]byte) string
}

type Hashable interface {
	Hash(hasher Hasher) []byte
	HashHex(hasher Hasher) string
}

// Convenience function around the hash interface to make implementation of the
// Hasher interface easier.
func hashBytes(hashFunc hash.Hash, input ...[]byte) []byte {
	for _, b := range input {
		hashFunc.Write(b)
	}
	return hashFunc.Sum(nil)
}

// Convenience function around the hash interface to make implementation of the
// Hasher interface easier.
func hashHex(hashFunc hash.Hash, input ...[]byte) string {
	return ToHex(hashBytes(hashFunc, input...))
}

type MockHasher struct {
	hex   string
	bytes []byte
}

func (h *MockHasher) Hash(input ...[]byte) []byte {
	return h.bytes
}

func (h *MockHasher) HashHex(input ...[]byte) string {
	return h.hex
}
