package crypto

import (
	"errors"

	"golang.org/x/crypto/ed25519"
)

// There are two curves commonly used in the 25519 family, c25519 and ed25519,
// they share some properties, for example the private and public key lengths.
// in casses where a propertly refers to either one, I've attempted to use the
// term x25519.
const (
	// X25519PrivateKeyLength Private key length for c25519 family of crypto primitives
	X25519PrivateKeyLength = 32
	// X25519PublicKeyLength Public key length for c25519 family of crypto primitives
	X25519PublicKeyLength = 32
	// X25519SignatureLength Signature length for c25519 family of crypto primitives
	X25519SignatureLength = 64
)

// NewEd25519Verifier constructor for ed25519 Verifier
func NewEd25519Verifier(pubKey []byte) (Verifier, error) {
	if len(pubKey) != X25519PublicKeyLength {
		return nil, errors.New("key should be 32 bytes got " + string(len(pubKey)))
	}
	return &ed25519Verifier{
		publicKey: pubKey,
		suiteType: "ed25519",
	}, nil
}

// NewEd25519Signer constructor for ed25519 Signer
func NewEd25519Signer(privKey []byte) (Signer, error) {
	if len(privKey) != X25519PrivateKeyLength {
		return nil, errors.New("key should be 32 bytes got " + string(len(privKey)))
	}
	// The ed25519 library depends on a private key that includes the public
	// and private key, so to get a private key you must pass a 32 byte private
	// key to the FromSeed function.
	key := ed25519.NewKeyFromSeed(privKey)
	verifier, verErr := NewEd25519Verifier(key[32:])
	if verErr != nil {
		return nil, verErr
	}
	return &ed25519Signer{
		privKey:  key,
		verifier: verifier,
	}, nil
}

// GenerateEd25519KeyPair a valid Curve25519 key pair.
func GenerateEd25519KeyPair() ([]byte, []byte, error) {
	pubKey, privKey, genErr := ed25519.GenerateKey(nil)
	// We take the first 32 bytes as the privKey as the private key. This is
	// because the underlying crypto library returns a private key that is
	// actually the private key with the public key appended to it.
	return privKey[:32], pubKey, genErr
}

// ed25519Verifier Verifies a signature using Curve25519 and ed25519
type ed25519Verifier struct {
	publicKey ed25519.PublicKey
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
	privKey  ed25519.PrivateKey
	verifier Verifier
}

func (s *ed25519Signer) Sign(toSign []byte) ([]byte, error) {
	return ed25519.Sign(s.privKey, toSign), nil
}

func (s *ed25519Signer) Verify(toVerify []byte, signature []byte) bool {
	return s.verifier.Verify(toVerify, signature)
}

func (s *ed25519Signer) SuiteType() string {
	return s.verifier.SuiteType()
}

func (s *ed25519Signer) Public() []byte {
	return s.privKey[32:]
}
