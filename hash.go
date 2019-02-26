package crypto

import (
	"hash"
)

type Hasher interface {
	Hash(input ...[]byte) []byte
	HashHex(input ...[]byte) string
}

// This interface's main purpose is to allow us to implement deterministic
// hashing behavior. For example, this is specifically separate than
// serialization format, which we may want to change over time or may vary
// depending on use case.
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

func NewByteHashable(toHash []byte) Hashable {
	return &ByteHashable{
		toHash: toHash,
	}
}

// A basic hashable type from a simple byte slice.
type ByteHashable struct {
	toHash []byte
}

func (h *ByteHashable) Hash(hasher Hasher) []byte {
	return hasher.Hash(h.toHash)
}

func (h *ByteHashable) HashHex(hasher Hasher) string {
	return hasher.HashHex(h.toHash)
}
