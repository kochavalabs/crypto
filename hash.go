package crypto

import (
	"hash"
)

type Hasher interface {
	Hash(input ...[]byte) []byte
	HashHex(input ...[]byte) string
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

// A Generic hasher that can implement the hasher interface when supplied with
// a golang standard library hash function.
// Any hasher created with this will not be thread safe.
type GenericHasher struct {
	hashFunc hash.Hash
}

func (h *GenericHasher) Hash(input ...[]byte) []byte {
	result := hashBytes(h.hashFunc, input...)
	h.hashFunc.Reset()
	return result
}

func (h *GenericHasher) HashHex(input ...[]byte) string {
	result := hashHex(h.hashFunc, input...)
	h.hashFunc.Reset()
	return result
}
