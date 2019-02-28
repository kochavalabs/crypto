package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
)

// MarhsalPrivateKeyX509 serialize a private key to DER-encoded format. (wrapper around x509 in crypto pkg )
func MarhsalPrivateKeyX509(prvk *ecdsa.PrivateKey) ([]byte, error) {
	x509EncodePubKey, err := x509.MarshalECPrivateKey(prvk)
	if err != nil {
		return nil, err
	}
	return x509EncodePubKey, nil
}

// UnmarshalX509PrivateKey parses an ASN.1 Elliptic Curve Private Key Structure (wrapper around x509 in crypto pkg)
func UnmarshalX509PrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// MarshaPublicKeyX509 serialize a public key to DER-encoded PKIX format. (wrapper around x509 in crypto pkg )
func MarshaPublicKeyX509(pubk *ecdsa.PublicKey) ([]byte, error) {
	x509EncodePubKey, err := x509.MarshalPKIXPublicKey(pubk)
	if err != nil {
		return nil, err
	}
	return x509EncodePubKey, nil
}

// UnmarshalPublicKeyX509 parses a DER encoded public key. (wrapper around x509 in crypto pkg)
func UnmarshalPublicKeyX509(der []byte) (*ecdsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	eckey := key.(*ecdsa.PublicKey)
	if err != nil {
		return nil, err
	}
	return (*ecdsa.PublicKey)(eckey), nil
}
