package crypto

import (
	"reflect"
	"testing"
)

func TestAddress(t *testing.T) {
	_, pubk, err := GenerateKeyPairP256()
	if err != nil {
		t.Error("Failed to generate keys")
	}
	address, err := AddressFromPublicKey(pubk)
	if err != nil {
		t.Error(err)
	}

	address2, err := AddressFromHex(address.Hex())
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(address, address2) {
		t.Error("address do not match")
	}
}
