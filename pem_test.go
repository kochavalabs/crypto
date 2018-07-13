package crypto

import (
	"reflect"
	"testing"
)

func TestPEMEncodeDecode(t *testing.T) {
	prv, pub, err := GenerateKeyPairP256()
	if err != nil {
		t.Error(err)
	}
	privPEMEncoded, _ := EncodePrivateKeyX509PEM(prv)
	if privPEMEncoded == nil {
		t.Error("failed to encode private key")
	}

	pubPEMEncoded, _ := EncodePublicKeyX509PEM(pub)
	if pubPEMEncoded == nil {
		t.Error("failed to encode public key")
	}

	derPriv, err := DecodeX509PEM(privPEMEncoded)
	if err != nil {
		t.Error("failed to decode PEM block for private key")
	}

	derPub, err := DecodeX509PEM(pubPEMEncoded)
	if err != nil {
		t.Error("failed to decode pem block for public key")
	}

	// now unmarhsal the x509 serilaized keys an verify we have the same
	prvKey, err := UnmarshalX509PrivateKey(derPriv)
	if err != nil {
		t.Error(err)
	}
	pubKey, err := UnmarshalPublicKeyX509(derPub)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(prv, prvKey) {
		t.Error("private keys do not match")
	}

	if !reflect.DeepEqual(pub, pubKey) {
		t.Error("public keys do not match")
	}

}
