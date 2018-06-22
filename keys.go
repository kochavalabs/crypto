package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// PrivateKeyByteLength defines the length in bytes of a serialized private key
const PrivateKeyBytesLength = 32

// Signature is a type representing an ECDSA signature
type Signature struct {
	R *big.Int
	S *big.Int
}

// TODO (elewis) : serialize signature to bytes
// func (sig *Signature) Serialize() []byte

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

// Serialize returns the private key number d as a big-endian binary-encoded
// number, padded to a length of 32 bytes.
func (prvk *PrivateKey) Serialize() []byte {
	b := make([]byte, 0, PrivateKeyBytesLength)
	return paddedAppend(PrivateKeyBytesLength, b, prvk.ToECDSA().D.Bytes())
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

// TODO (elewis) : Serialize to bytes
// func (pubk *PublicKey ) Serialize() []byte

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

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
