package crypto

import (
	"crypto/rand"
	"errors"
	"io"
)

// When using elliptic curves with ecdsa to sign messages, a possible
// vulnerability arises. If two messages are signed by the same key, it is
// possible to reverse engineer the private key. Because of this it was
// originally standardized to include a random number along with the signature
// to ensure that the same key was not used for two known messages. An
// alternative option is to hash the message + privateKey as the 'random'
// element of the signature to ensure that you never have the same key used
// for signing across different messages. This has the additional side effect
// of making singing deterministic where as choosing a random key causes
// indeterministic signing.
//
// This file contains some private helper functions for creating an io.Reader
// that will give either a random k or a determinist k based on the message
// and private key doing the signing.

// Gets a reader given private key data and the hash of a message to be signed.
type newReader func(hasher Hasher, messageHash []byte, privKey []byte) io.Reader

// Simply return a crypto/rand reader.
func newRandomReader(hasher Hasher, messageHash []byte, privKey []byte) io.Reader {
	return rand.Reader
}

// A deterministic reader of the form described above, returning a 'random'
// k based on the private key and message hash being used for the signing
// algorithm.
type deterministicReader struct {
	hasher      Hasher
	messageHash []byte
	privKey     []byte
}

func newDeterministicReader(hasher Hasher, messageHash []byte, privKey []byte) io.Reader {
	return &deterministicReader{
		hasher:      hasher,
		messageHash: messageHash,
		privKey:     privKey,
	}
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	digest := r.hasher.Hash(r.messageHash, r.privKey)
	if len(digest) < len(p) {
		return 0, errors.New("Missmatch between entropy length and hash length.")
	}
	for i, _ := range p {
		p[i] = digest[i]
	}
	return len(p), nil
}
