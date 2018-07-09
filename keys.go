package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
)

// PrivateKeyBytesLength defines the length in bytes of a serialized private key
const PrivateKeyBytesLength = 32

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

// ---------------------------
// exported utility functions
// ---------------------------

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

// KeyPairFromBytes todo
func KeyPairFromBytes(curve elliptic.Curve, pk []byte) (*PrivateKey, *PublicKey) {
	x, y := curve.ScalarBaseMult(pk)
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(pk),
	}
	return (*PrivateKey)(priv), (*PublicKey)(&priv.PublicKey)
}

// X509MarshalECPrivateKey marshals an EC private key into ASN.1, DER format. (wrapper around x509 in crypto pkg)
func X509MarshalECPrivateKey(key *PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(key.ToECDSA())
	if err != nil {
		return nil, err
	}
	return x509Encoded, nil
}

// X509MarhsalECPublicKey serialises a public key to DER-encoded PKIX format. (wrapper around x509 in crypto pkg)
func X509MarhsalECPublicKey(key *PublicKey) ([]byte, error) {
	x509EncodePubKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return x509EncodePubKey, nil
}

// X509UnmarshalECPrivateKey  parses an ASN.1 Elliptic Curve Private Key Structure (wrapper around x509 in crypto pkg)
func X509UnmarshalECPrivateKey(der []byte) (*PrivateKey, error) {
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, err
	}
	return (*PrivateKey)(key), nil
}

// X509UnmarshalECPublicKey parses a DER encoded public key. (wrapper around x509 in crypto pkg)
func X509UnmarshalECPublicKey(der []byte) (*PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	return key.(*PublicKey), nil
}

// PemEncodePrivateKey returns the PEM encoding of key
func PemEncodePrivateKey(key *PrivateKey) []byte {
	x509encoded, err := X509MarshalECPrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509encoded})
}

// PemEncodePublicKey returns the PEM encoding of key
func PemEncodePublicKey(key *PublicKey) []byte {
	x509encoded, err := X509MarhsalECPublicKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509encoded})
}

// PemDecodePrivateKey will find the next PEM formatted block (certificate, private key etc) in the input
// If no PEM data is found, PrivateKey will be nil and an error will be returned
func PemDecodePrivateKey(pemEncoded []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, errors.New("Missing block data")
	}
	prvKey, err := X509UnmarshalECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return prvKey, nil
}

// PemDecodePublicKey will find the next PEM formatted block (certificate, private key etc) in the input
// If no PEM data is found, PublicKey will be nil and an error will be returned
func PemDecodePublicKey(pemEncoded []byte) (*PublicKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, errors.New("Missing block data")
	}
	pubKey, err := X509UnmarshalECPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}
