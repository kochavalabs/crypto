package crypto

import (
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// EncodePrivateKeyX509PEM returns the DER-encoded PEM encoding of the private key
// returns PEM encoded bytes or nil if there is an error
func EncodePrivateKeyX509PEM(prv *PrivateKey) []byte {
	x509encoding, err := MarhsalPrivateKeyX509(prv)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509encoding})
}

// EncodePublicKeyX509PEM returns the DER-encoded PEM encoding of the public key
// returns PEM encoded bytes or nil if there is an error
func EncodePublicKeyX509PEM(pubk *PublicKey) []byte {
	x509encoding, err := MarshaPublicKeyX509(pubk)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509encoding})
}

// DecodeX509PEM returns a pem block as bytes or nil if no data is found
func DecodeX509PEM(pemEncoded []byte) ([]byte, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, errors.New("Unable to decode PEM Block data")
	}
	return block.Bytes, nil
}

// PrivateKeyFromPEMFile reads a X509 PEM encoded private key from file
// returns a private key or error
func PrivateKeyFromPEMFile(fileName string) (*PrivateKey, error) {
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
func PublicKeyFromPEMFile(fileName string) (*PublicKey, error) {
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
func PrivateKeyToPEMFile(fileName string, privateKey *PrivateKey) error {
	content := EncodePrivateKeyX509PEM(privateKey)
	if content == nil {
		return errors.New("Failed to encode private key")
	}
	err := ioutil.WriteFile(fileName, content, 0600)
	return err
}

// PublicKeyToPEMFile writes a X509 PEM encoded public key to a file
func PublicKeyToPEMFile(fileName string, publicKey *PublicKey) error {
	content := EncodePublicKeyX509PEM(publicKey)
	if content == nil {
		return errors.New("Failed to encode private key")
	}
	err := ioutil.WriteFile(fileName, content, 0600)
	return err
}
