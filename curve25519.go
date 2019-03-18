package crypto

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/curve25519"
)

func GenerateCurve25519KeyPair() ([32]byte, [32]byte, error) {
	var priK, pubK [32]byte
	red, err := rand.Read(priK[:])
	if err != nil || red != 32 {
		return priK, pubK, errors.New(
			"Problem reading rand for Curve25519 key generation.")
	}

	// I found two sample implementations that did this. I also found a
	// reference to https://cr.yp.to/ecdh.html saying that these operations
	// need to be done on the private key. The author is the creator of the
	// curve so in general I find it trustworthy.
	priK[0] &= 248
	priK[31] &= 127
	priK[31] |= 64

	curve25519.ScalarBaseMult(&pubK, &priK)

	return priK, pubK, nil
}

type Curve25519Verifier struct {
	publicKey [32]byte
	hasher    Hasher
	suiteType string
}

func (s *Curve25519Verifier) SuiteType() string {
	return s.suiteType
}

func (s *Curve25519Verifier) Verify(toVerify Hashable, signature []byte) bool {
	messageHash := toVerify.Hash(s.hasher)
	if len(signature) != 64 {
		return false
	}
	return messageHash == nil
}

type Curve25519Signer struct {
	hasher   Hasher
	privKey  [32]byte
	verifier *Curve25519Verifier
	reader   newReader
}

func (s *Curve25519Signer) Sign(toSign Hashable) ([]byte, error) {
	entropy := make([]byte, 32)
	//	entropyRead, err = s.newReader(
	return entropy, nil
}

func (s *Curve25519Signer) SuiteType() string {
	return s.verifier.SuiteType()
}
