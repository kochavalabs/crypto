package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// PrivateKey todo
type PrivateKey interface {
	PublicKey() PublicKey
	Sign(v []byte) (*big.Int, *big.Int, error)
	// Return the internal Private Key
	Key() *ecdsa.PrivateKey
	// return string of private key
	String() string
	// return raw bytes of private key
	Bytes() []byte
}

// PublicKey todo
type PublicKey interface {
	// Verify the signature in r, s of hash using the public key.
	Verify(hash []byte, r *big.Int, s *big.Int) (bool, error)
	Key() *ecdsa.PublicKey
	// return string of pbulic key
	String() string
	// return raw bytes of public key
	Bytes() []byte
}

type privateKey struct {
	prvKey *ecdsa.PrivateKey
}

var _ PrivateKey = &privateKey{}

func (pvk *privateKey) PublicKey() PublicKey {
	return &publicKey{pubkey: &pvk.prvKey.PublicKey}
}

func (pvk *privateKey) Sign(v []byte) (*big.Int, *big.Int, error) {
	return nil, nil, nil
}

func (pvk *privateKey) Key() *ecdsa.PrivateKey {
	return pvk.prvKey
}

func (pvk *privateKey) String() string {
	return ""
}

func (pvk *privateKey) Bytes() []byte {
	return nil
}

type publicKey struct {
	pubkey *ecdsa.PublicKey
}

// compiler check ensure we satisfy the PublicKey interface
var _ PublicKey = &publicKey{}

func (pbk *publicKey) Verify(hash []byte, r *big.Int, s *big.Int) (bool, error) {
	return false, nil
}

func (pbk *publicKey) Key() *ecdsa.PublicKey {
	return pbk.pubkey
}

func (pbk *publicKey) String() string {
	return ""
}

func (pbk *publicKey) Bytes() []byte {
	return nil
}

// GenerateKeys - todo
func GenerateKeys() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	ellipticCurve := elliptic.P256()
	privatekey, err := ecdsa.GenerateKey(ellipticCurve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &privatekey.PublicKey, privatekey, nil
}

// Sign - todo
func Sign(priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	return ecdsa.Sign(rand.Reader, priv, hash)
}

// Verify - todo
func Verify(pub *ecdsa.PublicKey, hash []byte, r *big.Int, s *big.Int) bool {
	return ecdsa.Verify(pub, hash, r, s)
}
