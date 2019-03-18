package crypto

import (
	"testing"
)

func TestCurve25519SuiteType(t *testing.T) {
	signer := Curve25519Signer{
		verifier: &Curve25519Verifier{suiteType: "Test"},
	}
	expected := "Test"
	result := signer.SuiteType()
	if expected != result {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}
