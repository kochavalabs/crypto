package crypto

import (
	"crypto/ecdsa"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// EncodePrivateKeyX509PEM returns the DER-encoded PEM encoding of the private key
// returns PEM encoded bytes or nil if there is an error
func EncodePrivateKeyX509PEM(prv *ecdsa.PrivateKey) ([]byte, error) {
	x509encoding, err := MarhsalPrivateKeyX509(prv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509encoding}), nil
}

// EncodePublicKeyX509PEM returns the DER-encoded PEM encoding of the public key
// returns PEM encoded bytes or nil if there is an error
func EncodePublicKeyX509PEM(pubk *ecdsa.PublicKey) ([]byte, error) {
	x509encoding, err := MarshaPublicKeyX509(pubk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509encoding}), nil
}

// DecodeX509PEM returns a pem block as bytes or nil if no data is found
func DecodeX509PEM(pemEncoded []byte) ([]byte, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, ErrDecodeX509PEM
	}
	return block.Bytes, nil
}

// PrivateKeyFromPEMFile reads a X509 PEM encoded private key from file
// returns a private key or error
func PrivateKeyFromPEMFile(fileName string) (*ecdsa.PrivateKey, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	der, err := DecodeX509PEM(content)
	if err != nil {
		return nil, err
	}
	prvk, err := UnmarshalX509PrivateKey(der)
	if err != nil {
		return nil, err
	}
	return prvk, nil
}

// PublicKeyFromPEMFile reads a X509 PEM encoded public key from file
// returns a public key or error
func PublicKeyFromPEMFile(fileName string) (*ecdsa.PublicKey, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	der, err := DecodeX509PEM(content)
	if err != nil {
		return nil, err
	}
	pubk, err := UnmarshalPublicKeyX509(der)
	if err != nil {
		return nil, err
	}
	return pubk, nil
}

// PrivateKeyToPEMFile writes a X509 PEM encoded private key to a file
func PrivateKeyToPEMFile(fileName string, privateKey *ecdsa.PrivateKey) error {
	content, err := EncodePrivateKeyX509PEM(privateKey)
	if err != nil {
		return err
	}
	if content == nil {
		return ErrPEMContentEmpty
	}
	if err := ioutil.WriteFile(fileName, content, 0600); err != nil {
		return err
	}
	return nil
}

// PublicKeyToPEMFile writes a X509 PEM encoded public key to a file
func PublicKeyToPEMFile(fileName string, publicKey *ecdsa.PublicKey) error {
	content, err := EncodePublicKeyX509PEM(publicKey)
	if err != nil {
		return err
	}
	if content == nil {
		return errors.New("Failed to encode private key")
	}
	if err := ioutil.WriteFile(fileName, content, 0600); err != nil {
		return err
	}
	return nil
}
