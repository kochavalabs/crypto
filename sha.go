package crypto

import (
	"crypto/sha256"
	"crypto/sha512"

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

// Sha3_512 is a SHA-3-512 hasher. Its generic security strength is
// 512 bits against preimage attacks, and 256 bits against collision attacks.
// data is an arbitrary length bytes slice returns 64 bytes ( 512 bits ) hash
// of data.
//
// Implements the crypto.Hasher interface.
type Sha3_512Hasher struct {
}

func (h *Sha3_512Hasher) Hash(input ...[]byte) []byte {
	return hashBytes(sha3.New512(), input...)
}

func (h *Sha3_512Hasher) HashHex(input ...[]byte) string {
	return hashHex(sha3.New512(), input...)
}

// Sha_256 is a SHA-256 hasher. Its generic security strength is
// 256 bits against preimage attacks, and 128 bits against collision attacks.
// data is an arbitrary length bytes slice returns 32 bytes ( 256 bits ) hash
// of data.
//
// Implements the crypto.Hasher interface.
type Sha_256Hasher struct {
}

func (h *Sha_256Hasher) Hash(input ...[]byte) []byte {
	return hashBytes(sha256.New(), input...)
}

func (h *Sha_256Hasher) HashHex(input ...[]byte) string {
	return hashHex(sha256.New(), input...)
}

// Sha_512 is a SHA-512 hasher. Its generic security strength is
// 512 bits against preimage attacks, and 256 bits against collision attacks.
// data is an arbitrary length bytes slice returns 64 bytes ( 512 bits ) hash
// of data.
//
// Implements the crypto.Hasher interface.
type Sha_512Hasher struct {
}

func (h *Sha_512Hasher) Hash(input ...[]byte) []byte {
	return hashBytes(sha512.New(), input...)
}

func (h *Sha_512Hasher) HashHex(input ...[]byte) string {
	return hashHex(sha512.New(), input...)
}
