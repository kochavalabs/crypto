package crypto

import (
	"golang.org/x/crypto/sha3"
)

// Sha3_256 is a SHA-3-256 hasher. Its generic security strength is
// 256 bits against preimage attacks, and 128 bits against collision attacks.
// data is an arbitrary length bytes slice
// returns 32 bytes ( 256 bits ) hash of data.
func Sha3_256(data ...[]byte) []byte {
	d := sha3.New256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Sha3_256ToHash calculates and returns the Sha256 hash of the input data,
// converting it to an internal Hash data structure.
func Sha3_256ToHash(data ...[]byte) (h Hash) {
	d := sha3.New256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}
