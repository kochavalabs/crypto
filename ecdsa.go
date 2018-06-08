package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// High level functions around Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3

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
