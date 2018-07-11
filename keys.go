package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// Signature is a type representing an ECDSA signature
type Signature struct {
	R *big.Int
	S *big.Int
}

// PrivateKey wraps an ecdsa.PrivateKey to provide convenience functions
type PrivateKey ecdsa.PrivateKey

// PubKey returns the public key assoicated with this private key
func (prvk *PrivateKey) PubKey() *PublicKey {
	return (*PublicKey)(&prvk.PublicKey)
}

// ToECDSA returns the underlying ecsda Private key
func (prvk *PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return (*ecdsa.PrivateKey)(prvk)
}

// Sign generates an ECDSA signature for the provided hash using the private key.
// **non deterministic**
func (prvk *PrivateKey) Sign(hash []byte) (*Signature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, prvk.ToECDSA(), hash)
	if err != nil {
		return nil, err
	}
	return &Signature{R: r, S: s}, nil
}

// PublicKey wraps an ecdsa.Public key for convenience
type PublicKey ecdsa.PublicKey

// ToECDSA returns the underlying ecsda Public Key
func (pubk *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return (*ecdsa.PublicKey)(pubk)
}

// Verify the signature of hash value. Returns true if the signature is
// generated with the private key assoicated with this public key
func (pubk *PublicKey) Verify(hash []byte, sig *Signature) bool {
	verified := ecdsa.Verify(pubk.ToECDSA(), hash, sig.R, sig.S)
	return verified
}

// GenerateKeyPair create a private/public key pair using an elliptic curve
func GenerateKeyPair(curve elliptic.Curve) (*PrivateKey, *PublicKey, error) {
	prvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return (*PrivateKey)(prvKey), (*PublicKey)(&prvKey.PublicKey), nil
}

// GenerateKeyPairP256 create a private/public key pair using the P256 elliptic curve
func GenerateKeyPairP256() (*PrivateKey, *PublicKey, error) {
	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return (*PrivateKey)(prvKey), (*PublicKey)(&prvKey.PublicKey), nil
}
