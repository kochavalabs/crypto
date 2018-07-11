package crypto

import (
	"reflect"
	"testing"
)

func TestMarshalling(t *testing.T) {
	prv, pub, err := GenerateKeyPairP256()
	if err != nil {
		t.Error(err)
	}
	derPriv, err := MarhsalPrivateKeyX509(prv)
	if err != nil {
		t.Error(err)
	}
	derPub, err := MarshaPublicKeyX509(pub)
	if err != nil {
		t.Error(err)
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

func TestDeterministicMarshalling(t *testing.T) {
	prv, pub, err := GenerateKeyPairP256()
	if err != nil {
		t.Error(err)
	}
	derPriv, err := MarhsalPrivateKeyX509(prv)
	if err != nil {
		t.Error(err)
	}
	derPriv2, err := MarhsalPrivateKeyX509(prv)
	if err != nil {
		t.Error(err)
	}
	derPub, err := MarshaPublicKeyX509(pub)
	if err != nil {
		t.Error(err)
	}
	derPub2, err := MarshaPublicKeyX509(pub)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(derPriv, derPriv2) {
		t.Error("Marhsalled keys do not match")
	}

	if !reflect.DeepEqual(derPub, derPub2) {
		t.Error("Marshalled keys do not match")
	}
}
