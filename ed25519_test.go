package crypto

import (
	"golang.org/x/crypto/ed25519"
	"reflect"
	"testing"
)

const Ed25519PubHex = "0x69ec35fafe61e514f4d2e54279671ab7e1e7fee9c4356da912ecd9f49db06773"
const Ed25519PrivHex = "0x3a547668e859fb7b112a1e2dd7efcb739176ab8cfd1d9f224847fce362ebd99c"
const EdMessageHex = "0x91b5963ab438f4ddf9dbdda98d50eab56fb8dbab24242fd86997ed99d89f0869549ea309d697e6d072c479ff1464b4831c902e40b45e181df506b6cda5be36f95cd9023270e902e2ad7ce1c1e09545fc25733cd9d155f6c65bac93006ac9f9c6a2fcf912e5fbf49277d553576b9853900c906adde560"
const EdSignatureHex = "0xb5aa14ad195fa99bcc1a0e77eb92903d6eb5fb387c3b71a3d19ac80ec86c1615251cc2ee0e06ba91319e5f56b893b03fb1160aa8dab4a72f69aa77be92d98d0c"

func TestEd25519SuiteType(t *testing.T) {
	signer := ed25519Signer{
		verifier: &ed25519Verifier{suiteType: "Test"},
	}
	expected := "Test"
	result := signer.SuiteType()
	if expected != result {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestEd25519Sign(t *testing.T) {
	toSign, _ := FromHex(EdMessageHex)
	privKey, _ := FromHex(Ed25519PrivHex)
	signer := ed25519Signer{
		privKey: ed25519.NewKeyFromSeed(privKey),
	}
	signature, sigErr := signer.Sign(toSign)

	if sigErr != nil {
		t.Errorf("Got a signature error %s", sigErr.Error())
	}
	expected, _ := FromHex(EdSignatureHex)
	if !reflect.DeepEqual(signature, expected) {
		t.Errorf("Expected %x, signature was %x.", expected, signature)
	}
}

func TestEd25519Verify(t *testing.T) {
	signature, _ := FromHex(EdSignatureHex)
	message, _ := FromHex(EdMessageHex)
	pubKey, _ := FromHex(Ed25519PubHex)
	verifier := ed25519Verifier{
		publicKey: pubKey,
	}
	result := verifier.Verify(message, signature)
	if !result {
		t.Errorf("Expected to verify signature.")
	}
}

func TestNewEd25519Verifier(t *testing.T) {
	signature, _ := FromHex(EdSignatureHex)
	pubKey, _ := FromHex(Ed25519PubHex)
	message, _ := FromHex(EdMessageHex)
	verifier, verErr := NewEd25519Verifier(pubKey)
	if verErr != nil {
		t.Errorf("Got a constructor error %s", verErr.Error())
	}

	result := verifier.Verify(message, signature)

	if !result {
		t.Errorf("Expected to verify signature.")
	}
	if verifier.SuiteType() != "ed25519" {
		t.Errorf("Expected suite type ed25519 got %s", verifier.SuiteType())
	}
}

func TestNewEd25519Signer(t *testing.T) {
	signature, _ := FromHex(EdSignatureHex)
	message, _ := FromHex(EdMessageHex)
	privKey, _ := FromHex(Ed25519PrivHex)
	signer, signerErr := NewEd25519Signer(privKey)
	if signerErr != nil {
		t.Errorf("Got a constructor error %s", signerErr.Error())
	}

	verifyResult := signer.Verify(message, signature)

	if !verifyResult {
		t.Errorf("Expected to verify signature.")
	}
	if signer.SuiteType() != "ed25519" {
		t.Errorf("Expected suite type ed25519 got %s", signer.SuiteType())
	}

	signResult, sigErr := signer.Sign(message)

	if sigErr != nil {
		t.Errorf("Got a sign error %s", sigErr.Error())
	}

	if !reflect.DeepEqual(signResult, signature) {
		t.Errorf("Expected %x, signature was %x.", signature, signResult)
	}

}

func TestNewEd25519KeySize(t *testing.T) {
	key := []byte{1, 2, 3}
	_, sigErr := NewEd25519Signer(key)
	_, verErr := NewEd25519Verifier(key)

	if sigErr == nil {
		t.Errorf("Did not get signature error.")
	}

	if verErr == nil {
		t.Errorf("Did not get verifier error.")
	}
}
