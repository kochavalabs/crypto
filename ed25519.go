package crypto

import (
	"golang.org/x/crypto/ed25519"
)

const (
	X25519PrivateKeyLength = 32
	X25519PublicKeyLength  = 32
	X25519SignatureLength  = 64
)

// GenerateEd25519KeyPair a valid Curve25519 key pair.
func GenerateEd25519KeyPair() ([]byte, []byte, error) {
	pubKey, privKey, genErr := ed25519.GenerateKey(nil)
	return privKey[:32], pubKey, genErr
}

// ed25519Verifier Verifies a signature using Curve25519 and ed25519
type ed25519Verifier struct {
	publicKey []byte
	suiteType string
}

func (s *ed25519Verifier) SuiteType() string {
	return s.suiteType
}

func (s *ed25519Verifier) Verify(toVerify []byte, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	return ed25519.Verify(s.publicKey, toVerify, signature)
}

type ed25519Signer struct {
	privKey  []byte
	verifier *ed25519Verifier
	reader   newReader
}

func (s *ed25519Signer) Sign(toSign []byte) ([]byte, error) {
	key := ed25519.NewKeyFromSeed(s.privKey)
	return ed25519.Sign(key, toSign), nil
}

func (s *ed25519Signer) SuiteType() string {
	return s.verifier.SuiteType()
}
