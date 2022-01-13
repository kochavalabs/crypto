package crypto

import (
	"errors"
	"fmt"

	"crypto/ed25519"
)

// There are two curves commonly used in the 25519 family, c25519 and ed25519,
// they share some properties, for example the private and public key lengths.
// in casses where a propertly refers to either one use the
// term x25519.
const (
	// X25519PrivateKeyLength Private key length for c25519 family of crypto primitives
	X25519PrivateKeyLength = 64
	// X25519PublicKeyLength Public key length for c25519 family of crypto primitives
	X25519PublicKeyLength = 32
	// X25519SignatureLength Signature length for c25519 family of crypto primitives
	X25519SignatureLength = 64
)

// NewEd25519Verifier constructor for ed25519 Verifier
func NewEd25519Verifier(pubKey []byte) (Verifier, error) {
	if len(pubKey) != X25519PublicKeyLength {
		return nil, errors.New("key should be 32 bytes got " + fmt.Sprint(len(pubKey)))
	}
	return &ed25519Verifier{
		publicKey: pubKey,
		suiteType: "ed25519",
	}, nil
}

// NewEd25519Signer constructor for ed25519 Signer
func NewEd25519Signer(privKey []byte) (Signer, error) {
	if len(privKey) != X25519PrivateKeyLength {
		return nil, errors.New("key should be 64 bytes got " + fmt.Sprint(len(privKey)))
	}

	verifier, verErr := NewEd25519Verifier(privKey[32:])
	if verErr != nil {
		return nil, verErr
	}

	return &ed25519Signer{
		privKey:  privKey,
		verifier: verifier,
	}, nil
}

// GenerateEd25519KeyPair a valid Curve25519 key pair.
func GenerateEd25519KeyPair() (pub []byte, priv []byte, err error) {
	return ed25519.GenerateKey(nil)
}

// Ed25519PublicKeyFromPrivate return the public key associated with a private key for Curve25519.
func Ed25519PublicKeyFromPrivate(privKey []byte) ([]byte, error) {
	if len(privKey) != X25519PrivateKeyLength {
		return nil, errors.New("key should be 64 bytes got " + fmt.Sprint(len(privKey)))
	}
	// last 32 bytes of the private key are the public key
	return privKey[32:], nil
}

func Ed25519KeyPairFromSeed(seed []byte) (pub []byte, priv []byte, err error) {
	if len(seed) != 32 {
		return nil, nil, errors.New("invalid seed length, seed must be 32 bytes")
	}
	priv = ed25519.NewKeyFromSeed(seed)
	pub = priv[32:]
	return pub, priv, nil
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
